use std::{
    ffi::OsString,
    future::Future,
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

use clap::Command;
use log::{error, info};
use shadowsocks_rust::{
    error::ShadowsocksResult,
    service::{local, manager, server},
};
use tokio::{runtime::Runtime, sync::oneshot};
use windows_service::{
    define_windows_service,
    service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType},
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
};

const SERVICE_NAME: &str = "ssservice";
const SERVICE_EXIT_CODE_ARGUMENT_ERROR: u32 = 100;
const SERVICE_EXIT_CODE_EXITED_UNEXPECTLY: u32 = 101;
const SERVICE_EXIT_CODE_CREATE_FAILED: u32 = 102;

#[inline]
fn set_service_status(
    handle: &ServiceStatusHandle,
    current_state: ServiceState,
    exit_code: ServiceExitCode,
    wait_hint: Duration,
) -> Result<(), windows_service::Error> {
    static SERVICE_STATE_CHECKPOINT: AtomicU32 = AtomicU32::new(0);

    let next_status = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state,
        controls_accepted: if current_state == ServiceState::StartPending {
            ServiceControlAccept::empty()
        } else {
            ServiceControlAccept::STOP
        },
        exit_code,
        checkpoint: if matches!(current_state, ServiceState::Running | ServiceState::Stopped) {
            SERVICE_STATE_CHECKPOINT.fetch_add(1, Ordering::AcqRel)
        } else {
            0
        },
        wait_hint,
        process_id: None,
    };
    handle.set_service_status(next_status)
}

fn handle_create_service_result<F>(
    status_handle: ServiceStatusHandle,
    create_service_result: ShadowsocksResult<(Runtime, F)>,
    stop_receiver: oneshot::Receiver<()>,
) -> Result<(), windows_service::Error>
where
    F: Future<Output = ShadowsocksResult>,
{
    match create_service_result {
        Ok((runtime, main_fut)) => {
            // Successfully create runtime and future

            // Report running state
            set_service_status(
                &status_handle,
                ServiceState::Running,
                ServiceExitCode::Win32(0),
                Duration::default(),
            )?;

            // Run it right now.
            let exited_by_ctrl = runtime.block_on(async move {
                tokio::pin!(main_fut);
                tokio::pin!(stop_receiver);

                loop {
                    tokio::select! {
                        _ = stop_receiver => {
                            break true;
                        }
                        exit_code = main_fut => {
                            info!("service exited unexpectly with code: {:?}", exit_code);
                            break false;
                        }
                    }
                }
            });

            // Report stopped state
            set_service_status(
                &status_handle,
                ServiceState::Stopped,
                if exited_by_ctrl {
                    ServiceExitCode::Win32(0)
                } else {
                    ServiceExitCode::ServiceSpecific(SERVICE_EXIT_CODE_EXITED_UNEXPECTLY)
                },
                Duration::default(),
            )?;
        }
        Err(err) => {
            error!("failed to create service, exit code: {:?}", err.exit_code());

            // Report running state
            set_service_status(
                &status_handle,
                ServiceState::Stopped,
                ServiceExitCode::ServiceSpecific(SERVICE_EXIT_CODE_CREATE_FAILED),
                Duration::default(),
            )?;
        }
    }

    Ok(())
}

fn service_main(arguments: Vec<OsString>) -> Result<(), windows_service::Error> {
    // Create a Oneshot channel for receiving Stop event
    let (stop_sender, stop_receiver) = oneshot::channel();

    let mut stop_sender_opt = Some(stop_sender);
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                if let Some(stop_sender) = stop_sender_opt.take() {
                    let _ = stop_sender.send(());
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    // Register system service event handler
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    // Report SERVICE_START_PENDING
    // https://learn.microsoft.com/en-us/windows/win32/services/writing-a-servicemain-function
    set_service_status(
        &status_handle,
        ServiceState::StartPending,
        ServiceExitCode::Win32(0),
        Duration::from_secs(30),
    )?;

    let app = Command::new("shadowsocks service")
        .version(shadowsocks_rust::VERSION)
        .about("A fast tunnel proxy that helps you bypass firewalls. (https://shadowsocks.org)");

    let app = app
        .subcommand_required(true)
        .subcommand(local::define_command_line_options(Command::new("local")).about("Shadowsocks Local service"))
        .subcommand(server::define_command_line_options(Command::new("server")).about("Shadowsocks Server service"))
        .subcommand(
            manager::define_command_line_options(Command::new("manager")).about("Shadowsocks Server Manager service"),
        );

    let matches_result = if arguments.len() <= 1 {
        app.try_get_matches()
    } else {
        app.try_get_matches_from(arguments)
    };

    let matches = match matches_result {
        Ok(m) => m,
        Err(err) => {
            error!("failed to parse command line arguments, error: {}", err);
            set_service_status(
                &status_handle,
                ServiceState::Stopped,
                ServiceExitCode::ServiceSpecific(SERVICE_EXIT_CODE_ARGUMENT_ERROR),
                Duration::default(),
            )?;
            return Err(windows_service::Error::LaunchArgumentsNotSupported);
        }
    };

    match matches.subcommand() {
        Some(("local", matches)) => handle_create_service_result(status_handle, local::create(matches), stop_receiver),
        Some(("server", matches)) => {
            handle_create_service_result(status_handle, server::create(matches), stop_receiver)
        }
        Some(("manager", matches)) => {
            handle_create_service_result(status_handle, manager::create(matches), stop_receiver)
        }
        _ => Err(windows_service::Error::LaunchArgumentsNotSupported),
    }
}

fn service_entry(arguments: Vec<OsString>) {
    if let Err(err) = service_main(arguments) {
        error!("service main exited with error: {}", err);
    }
}

define_windows_service!(ffi_service_entry, service_entry);

fn main() -> Result<(), windows_service::Error> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_entry)?;
    Ok(())
}
