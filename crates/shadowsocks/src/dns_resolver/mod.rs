//! Asynchronous DNS resolver
#![macro_use]

pub use self::resolver::{DnsResolve, DnsResolver};

#[cfg(feature = "hickory-dns")]
mod hickory_dns_resolver;
mod resolver;

/// Helper macro for resolving host and then process each addresses
#[macro_export]
macro_rules! lookup_then {
    ($context:expr_2021, $addr:expr_2021, $port:expr_2021, |$resolved_addr:ident| $body:block) => {{
        use std::net::SocketAddr;

        let ipv6_first = $context.ipv6_first();

        let mut v4_addrs = Vec::new();
        let mut v6_addrs = Vec::new();

        for addr in $context.dns_resolve($addr, $port).await? {
            match addr {
                SocketAddr::V4(..) => v4_addrs.push(addr),
                SocketAddr::V6(..) => v6_addrs.push(addr),
            }
        }

        let has_v4 = !v4_addrs.is_empty();
        let has_v6 = !v6_addrs.is_empty();

        assert!(has_v4 || has_v6, "resolved empty address");

        if !has_v4 && has_v6 {
            lookup_then!(RESOLVE @ v6_addrs, $resolved_addr, $body)
        } else if has_v4 && !has_v6 {
            lookup_then!(RESOLVE @ v4_addrs, $resolved_addr, $body)
        } else {
            if ipv6_first {
                match lookup_then!(RESOLVE @ v6_addrs, $resolved_addr, $body) {
                    Ok(r) => Ok(r),
                    Err(_v6_err) => lookup_then!(RESOLVE @ v4_addrs, $resolved_addr, $body),
                }
            } else {
                match lookup_then!(RESOLVE @ v4_addrs, $resolved_addr, $body) {
                    Ok(r) => Ok(r),
                    Err(_v4_err) => lookup_then!(RESOLVE @ v6_addrs, $resolved_addr, $body),
                }
            }
        }
    }};

    (RESOLVE @ $addrs:expr_2021, $resolved_addr:ident, $body:block) => {{
        let mut result = None;

        for $resolved_addr in $addrs {
            match $body {
                Ok(r) => {
                    result = Some(Ok(($resolved_addr, r)));
                    break;
                }
                Err(err) => {
                    result = Some(Err(err));
                }
            }
        }

        result.expect("resolved empty address")
    }};
}

#[macro_export]
macro_rules! lookup_then_connect {
    ($context:expr_2021, $addr:expr_2021, $port:expr_2021, |$resolved_addr:ident| $body:block) => {{
        use futures::future::{self, Either};
        use log::trace;
        use std::{net::SocketAddr, time::Duration};
        use tokio::time;

        let ipv6_first = $context.ipv6_first();

        let mut v4_addrs = Vec::new();
        let mut v6_addrs = Vec::new();

        for addr in $context.dns_resolve($addr, $port).await? {
            match addr {
                SocketAddr::V4(..) => v4_addrs.push(addr),
                SocketAddr::V6(..) => v6_addrs.push(addr),
            }
        }

        let has_v4 = !v4_addrs.is_empty();
        let has_v6 = !v6_addrs.is_empty();

        assert!(has_v4 || has_v6, "resolved empty address");

        // Happy Eyeballs, RFC6555, RFC8305
        //
        // RFC6555 gives an example that Chrome and Firefox uses 300ms
        const FIXED_DELAY: Duration = Duration::from_millis(300);

        // Connects every addresses synchronously.
        // TODO: Try another address after FIXED_DELAY if one of the IPs is unreachable.
        //
        // This would require `future::select_ok`, which will require futures to be `Unpin`
        // (boxed future, excessive memory allocation).

        let connect_v4 = async {
            // use futures::FutureExt;
            //
            // let mut vfut = Vec::new();
            //
            // let mut delay = Duration::from_millis(0);
            //
            // for $resolved_addr in v4_addrs {
            //     vfut.push(
            //         async move {
            //             if delay != Duration::from_millis(0) {
            //                 time::sleep(delay).await;
            //             }
            //
            //             trace!("trying connect {}:{} {}", $addr, $port, $resolved_addr);
            //
            //             match $body {
            //                 Ok(r) => Ok(($resolved_addr, r)),
            //                 Err(err) => Err(err),
            //             }
            //         }
            //         .boxed(),
            //     );
            //
            //     delay += FIXED_DELAY;
            // }
            //
            // match future::select_ok(vfut).await {
            //     Ok((r, _)) => Ok(r),
            //     Err(err) => Err(err),
            // }

            let mut result = None;

            for $resolved_addr in v4_addrs {
                trace!("trying connect {}:{} {}", $addr, $port, $resolved_addr);

                match $body {
                    Ok(r) => {
                        trace!("connected {}:{} {}", $addr, $port, $resolved_addr);
                        result = Some(Ok(($resolved_addr, r)));
                        break;
                    }
                    Err(err) => {
                        result = Some(Err(err));
                    }
                }
            }

            result.expect("impossible")
        };

        let connect_v6 = async {
            let mut result = None;

            for $resolved_addr in v6_addrs {
                trace!("trying connect {}:{} {}", $addr, $port, $resolved_addr);

                match $body {
                    Ok(r) => {
                        trace!("connected {}:{} {}", $addr, $port, $resolved_addr);
                        result = Some(Ok(($resolved_addr, r)));
                        break;
                    }
                    Err(err) => {
                        result = Some(Err(err));
                    }
                }
            }

            result.expect("impossible")
        };

        if has_v4 && !has_v6 {
            connect_v4.await
        } else if !has_v4 && has_v6 {
            connect_v6.await
        } else {
            if ipv6_first {
                let v4_fut = async move {
                    time::sleep(FIXED_DELAY).await;
                    connect_v4.await
                };
                let v6_fut = connect_v6;

                tokio::pin!(v4_fut);
                tokio::pin!(v6_fut);

                match future::select(v4_fut, v6_fut).await {
                    Either::Left((v4_res, v6_fut)) => match v4_res {
                        Ok(res) => Ok(res),
                        Err(_v4_err) => v6_fut.await,
                    },
                    Either::Right((v6_res, v4_fut)) => match v6_res {
                        Ok(res) => Ok(res),
                        Err(_v6_err) => v4_fut.await,
                    },
                }
            } else {
                let v6_fut = async move {
                    time::sleep(FIXED_DELAY).await;
                    connect_v6.await
                };
                let v4_fut = connect_v4;

                tokio::pin!(v4_fut);
                tokio::pin!(v6_fut);

                match future::select(v4_fut, v6_fut).await {
                    Either::Left((v4_res, v6_fut)) => match v4_res {
                        Ok(res) => Ok(res),
                        Err(_v4_err) => v6_fut.await,
                    },
                    Either::Right((v6_res, v4_fut)) => match v6_res {
                        Ok(res) => Ok(res),
                        Err(_v6_err) => v4_fut.await,
                    },
                }
            }
        }
    }};
}
