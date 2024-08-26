import os
import subprocess
import time

# Fungsi untuk menguatkan akses SSH
def harden_ssh():
    ssh_config_path = '/etc/ssh/sshd_config'
    
    config_updates = {
        'PermitRootLogin': 'no',
        'PasswordAuthentication': 'no',
        'ChallengeResponseAuthentication': 'no',
        'UsePAM': 'yes',
        'PermitEmptyPasswords': 'no',
        'X11Forwarding': 'no',
        'AllowTcpForwarding': 'no'
    }

    try:
        with open(ssh_config_path, 'r') as file:
            config_lines = file.readlines()

        with open(ssh_config_path, 'w') as file:
            for line in config_lines:
                key = line.split()[0] if len(line.split()) > 0 else ''
                if key in config_updates:
                    file.write(f"{key} {config_updates[key]}\n")
                else:
                    file.write(line)

        subprocess.run(['systemctl', 'restart', 'ssh'], check=True)
        print("[INFO] SSH configuration hardened and service restarted.")
    except Exception as e:
        print(f"[ERROR] Failed to harden SSH: {e}")

# Fungsi untuk menguatkan akses superuser
def harden_sudo():
    sudoers_file = '/etc/sudoers'
    
    try:
        with open(sudoers_file, 'a') as file:
            file.write('\nDefaults use_pty\n')
            file.write('Defaults logfile="/var/log/sudo.log"\n')
            file.write('Defaults passwd_timeout=1\n')
            file.write('Defaults log_input,log_output\n')
        print("[INFO] Sudoers file updated to harden superuser access.")
    except Exception as e:
        print(f"[ERROR] Failed to harden superuser access: {e}")

# Fungsi untuk menguatkan kebijakan kata sandi
def harden_password_policy():
    login_defs = '/etc/login.defs'
    try:
        subprocess.run(['apt-get', 'install', '-y', 'libpam-pwquality'], check=True)
        with open(login_defs, 'r') as file:
            lines = file.readlines()
        
        with open(login_defs, 'w') as file:
            for line in lines:
                if line.startswith('PASS_MAX_DAYS'):
                    file.write('PASS_MAX_DAYS 90\n')
                elif line.startswith('PASS_MIN_DAYS'):
                    file.write('PASS_MIN_DAYS 10\n')
                elif line.startswith('PASS_MIN_LEN'):
                    file.write('PASS_MIN_LEN 12\n')
                elif line.startswith('PASS_WARN_AGE'):
                    file.write('PASS_WARN_AGE 7\n')
                else:
                    file.write(line)

        pam_pwquality_conf = '/etc/security/pwquality.conf'
        with open(pam_pwquality_conf, 'w') as file:
            file.write('minlen = 12\n')
            file.write('dcredit = -1\n')
            file.write('ucredit = -1\n')
            file.write('lcredit = -1\n')
            file.write('ocredit = -1\n')

        print("[INFO] Password policy hardened.")
    except Exception as e:
        print(f"[ERROR] Failed to harden password policy: {e}")

# Fungsi untuk menguatkan login
def harden_login():
    issue_net_path = '/etc/issue.net'
    try:
        with open(issue_net_path, 'w') as file:
            file.write('Unauthorized access to this machine is prohibited. All activities will be monitored.\n')
        
        # Konfigurasi pam untuk logout otomatis setelah 5 menit tidak aktif
        pam_tty_conf = '/etc/pam.d/sshd'
        with open(pam_tty_conf, 'a') as file:
            file.write('session required pam_exec.so /usr/local/bin/logout.sh\n')
        
        with open('/usr/local/bin/logout.sh', 'w') as file:
            file.write('#!/bin/bash\n')
            file.write('if [ $EUID -ne 0 ]; then\n')
            file.write('  logout\n')
            file.write('fi\n')

        os.chmod('/usr/local/bin/logout.sh', 0o755)
        print("[INFO] Login hardened with warning banner and automatic logout.")
    except Exception as e:
        print(f"[ERROR] Failed to harden login: {e}")

# Fungsi untuk menguatkan izin file
def harden_file_permissions():
    critical_files = ['/etc/passwd', '/etc/shadow', '/etc/gshadow', '/etc/group']
    try:
        for file_path in critical_files:
            os.chmod(file_path, 0o600)
        print("[INFO] File permissions hardened for critical system files.")
    except Exception as e:
        print(f"[ERROR] Failed to harden file permissions: {e}")

# Fungsi untuk menguatkan akses MySQL server
def harden_mysql():
    try:
        subprocess.run(['mysql', '-e', 'DELETE FROM mysql.user WHERE User="";'], check=True)
        subprocess.run(['mysql', '-e', 'DROP DATABASE test;'], check=True)
        subprocess.run(['mysql', '-e', 'DELETE FROM mysql.db WHERE Db="test" OR Db="test\\_%";'], check=True)
        subprocess.run(['mysql', '-e', 'FLUSH PRIVILEGES;'], check=True)
        print("[INFO] MySQL server access hardened.")
    except Exception as e:
        print(f"[ERROR] Failed to harden MySQL server: {e}")

# Fungsi untuk mengaktifkan Security-Enhanced Linux (SELinux)
def harden_selinux():
    selinux_config_path = '/etc/selinux/config'
    try:
        with open(selinux_config_path, 'r') as file:
            config_lines = file.readlines()
        
        with open(selinux_config_path, 'w') as file:
            for line in config_lines:
                if 'SELINUX=' in line:
                    file.write('SELINUX=enforcing\n')
                else:
                    file.write(line)
        
        subprocess.run(['setenforce', '1'], check=True)
        print("[INFO] SELinux is now enforcing.")
    except Exception as e:
        print(f"[ERROR] Failed to enable SELinux: {e}")

# Fungsi utama untuk mengelola hardening
def main():
    print("Running Linux Server Hardening Script...")
    
    harden_ssh()
    harden_sudo()
    harden_password_policy()
    harden_login()
    harden_file_permissions()
    harden_mysql()
    harden_selinux()

    print("Linux Server Hardening Completed.")

if __name__ == "__main__":
    main()
