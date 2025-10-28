use aws::{get_entropy, init_platform};
use std::env;
use std::process::Command;
use system::{dmesg, freopen, mount, reboot, seed_entropy};

fn init_rootfs() {
    use libc::{MS_NODEV, MS_NOEXEC, MS_NOSUID};
    let no_dse = MS_NODEV | MS_NOSUID | MS_NOEXEC;
    let no_se = MS_NOSUID | MS_NOEXEC;
    let args = [
        ("devtmpfs", "/dev", "devtmpfs", no_se, "mode=0755"),
        ("devpts", "/dev/pts", "devpts", no_se, ""),
        ("shm", "/dev/shm", "tmpfs", no_dse, "mode=0755"),
        ("proc", "/proc", "proc", no_dse, "hidepid=2"),
        ("tmpfs", "/run", "tmpfs", no_dse, "mode=0755"),
        ("tmpfs", "/tmp", "tmpfs", no_dse, ""),
        ("sysfs", "/sys", "sysfs", no_dse, ""),
        (
            "cgroup_root",
            "/sys/fs/cgroup",
            "tmpfs",
            no_dse,
            "mode=0755",
        ),
    ];
    for (src, target, fstype, flags, data) in args {
        match std::fs::create_dir_all(target) {
            Ok(()) => dmesg(format!("Created mount point {}", target)),
            Err(e) => eprintln!("Failed to create {}: {}", target, e),
        }
        match mount(src, target, fstype, flags, data) {
            Ok(()) => dmesg(format!("Mounted {}", target)),
            Err(e) => eprintln!("Failed to mount {}: {}", target, e),
        }
    }
}

fn init_console() {
    let args = [
        ("/dev/console", "r", 0),
        ("/dev/console", "w", 1),
        ("/dev/console", "w", 2),
    ];
    for (filename, mode, file) in args {
        match freopen(filename, mode, file) {
            Ok(()) => {}
            Err(e) => eprintln!("{}", e),
        }
    }
}

fn boot() {
    init_rootfs();
    init_console();
    init_platform();
    match seed_entropy(4096, get_entropy) {
        Ok(size) => dmesg(format!("Seeded kernel with entropy: {}", size)),
        Err(e) => eprintln!("{}", e),
    };
}

fn main() {
    boot();
    dmesg("Caution Enclave Booted".to_string());

    // Set basic environment
    env::set_var("PATH", "/bin:/sbin:/usr/bin:/usr/sbin:/");

    // Execute our shell-based init script
    match Command::new("/bin/sh").arg("/init.sh").spawn() {
        Ok(mut child) => {
            dmesg("Spawned init.sh script".to_string());
            // Wait for the child process to finish
            match child.wait() {
                Ok(status) => dmesg(format!("init.sh exited with status: {}", status)),
                Err(e) => eprintln!("Error waiting for init.sh: {}", e),
            }
        }
        Err(e) => {
            eprintln!("FATAL: Failed to execute /bin/sh /init.sh: {}", e);
            eprintln!("This likely means busybox or init.sh is missing from initramfs");
        }
    }

    dmesg("Enclave shutting down".to_string());
    reboot();
}
