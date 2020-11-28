//! UDP relay proxy server

use std::{io, sync::Arc, time::Duration};

use futures::{stream::FuturesUnordered, StreamExt};
use log::{debug, error, info, trace, warn};
use tokio::{self, time};

use crate::{
    context::SharedContext,
    relay::{
        flow::{SharedMultiServerFlowStatistic, SharedServerFlowStatistic},
        sys::create_udp_socket,
    },
};

use super::{
    association::{ServerAssociation, ServerAssociationManager, ServerProxyHandler},
    MAXIMUM_UDP_PAYLOAD_SIZE,
};

async fn listen(context: SharedContext, flow_stat: SharedServerFlowStatistic, svr_idx: usize) -> io::Result<()> {
    let svr_cfg = context.server_config(svr_idx);
    let listen_addr = svr_cfg.addr().bind_addr(&context).await?;

    let listener = create_udp_socket(&listen_addr).await?;
    let local_addr = listener.local_addr().expect("determine port bound to");
    info!("shadowsocks UDP listening on {}", local_addr);

    let r = Arc::new(listener);
    let w = r.clone();

    let assoc_manager = ServerAssociationManager::new(context.config());

    let mut pkt_buf = vec![0u8; MAXIMUM_UDP_PAYLOAD_SIZE];

    loop {
        let (recv_len, src) = match r.recv_from(&mut pkt_buf).await {
            Ok(o) => o,
            Err(err) => {
                error!("recv_from failed with err: {}", err);
                time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        // Packet length is limited by MAXIMUM_UDP_PAYLOAD_SIZE, excess bytes will be discarded.
        let pkt = &pkt_buf[..recv_len];

        trace!("received UDP packet from {}, length {} bytes", src, recv_len);
        flow_stat.udp().incr_rx(pkt.len());

        if recv_len == 0 {
            // For windows, it will generate a ICMP Port Unreachable Message
            // https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-recvfrom
            // Which will result in recv_from return 0.
            //
            // It cannot be solved here, because `WSAGetLastError` is already set.
            //
            // See `relay::udprelay::utils::create_socket` for more detail.
            continue;
        }

        // Check ACL
        if context.check_client_blocked(&src).await {
            warn!("client {} is blocked by ACL rules", src);
            continue;
        }

        // Check or (re)create an association
        let res = assoc_manager
            .send_packet(ServerProxyHandler::association_key(&src), pkt.to_vec(), async {
                let handler = ServerProxyHandler::new(src, assoc_manager.clone(), flow_stat.clone(), w.clone());
                ServerAssociation::associate(context.clone(), svr_idx, src, handler).await
            })
            .await;

        if let Err(err) = res {
            debug!("failed to create UDP association, {}", err);
        }
    }
}

/// Starts a UDP relay server
pub async fn run(context: SharedContext, flow_stat: SharedMultiServerFlowStatistic) -> io::Result<()> {
    let vec_fut = FuturesUnordered::new();

    for (svr_idx, svr_cfg) in context.config().server.iter().enumerate() {
        let context = context.clone();
        let flow_stat = flow_stat
            .get(svr_cfg.addr().port())
            .expect("port not existed in multi-server flow statistic")
            .clone();

        let svr_fut = listen(context, flow_stat, svr_idx);
        vec_fut.push(svr_fut);
    }

    match vec_fut.into_future().await.0 {
        Some(res) => {
            error!("one of UDP servers exited unexpectly, result: {:?}", res);
            let err = io::Error::new(io::ErrorKind::Other, "server exited unexpectly");
            Err(err)
        }
        None => unreachable!(),
    }
}
