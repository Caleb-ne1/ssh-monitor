import os
import sys

import yaml
import re
import time
from utils.alerts import send_email
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from config.setup_config import load_config, CONFIG_FILE




# load config
config = load_config()

AUTH_LOG = config.get("auth_log", "/var/log/auth.log")

# regex patterns
SUCCESS_REGEX = re.compile(
    r"Accepted (password|publickey|keyboard-interactive) for (\S+) from ([\d\.]+) port (\d+)"
)
FAIL_REGEX = re.compile(
    r"(Failed password|Invalid user) for (\S+) from ([\d\.]+) port (\d+)"
)
CLOSE_REGEX = re.compile(
    r"(Disconnected from|Connection closed by).*?([\d\.]+) port (\d+)"
)

# active sessions tracking
active_sessions = set()

# failed attempts aggregation
failed_attempts = {}  
FAIL_THRESHOLD = 5    
TIME_WINDOW = 60     

# success login
def build_success_email(user, ip, port, method):
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSH Success Alert</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background-color: #0a0c10;
            line-height: 1.6;
        }}
        .email-wrapper {{
            max-width: 600px;
            margin: 20px auto;
            background: #0f1117;
            border: 1px solid #2a2f3a;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.5);
        }}
        .header {{
            background: #0b1a1a;
            padding: 24px 32px;
            border-bottom: 2px solid #1f8b4c;
        }}
        .header-content {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .status-icon {{
            width: 48px;
            height: 48px;
            background: #1f8b4c;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            color: #ffffff;
        }}
        .header-text {{
            flex: 1;
        }}
        .header-text h1 {{
            color: #e5e9f0;
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 4px;
        }}
        .header-text .badge {{
            color: #9fefb7;
            font-size: 14px;
            font-weight: 500;
            background: rgba(31, 139, 76, 0.2);
            padding: 4px 12px;
            border-radius: 20px;
            display: inline-block;
        }}
        .content {{
            padding: 32px;
            background: #0f1117;
        }}
        .info-grid {{
            background: #1a1e26;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 24px;
            border: 1px solid #2a2f3a;
        }}
        .info-row {{
            display: flex;
            padding: 12px 0;
            border-bottom: 1px solid #2a2f3a;
        }}
        .info-row:last-child {{
            border-bottom: none;
        }}
        .info-label {{
            width: 140px;
            color: #8b949e;
            font-size: 14px;
            font-weight: 500;
        }}
        .info-value {{
            flex: 1;
            color: #e5e9f0;
            font-size: 15px;
            font-weight: 500;
        }}
        .method-tag {{
            background: #1f8b4c20;
            color: #9fefb7;
            padding: 4px 12px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 600;
            border: 1px solid #1f8b4c40;
        }}
        .ip-block {{
            font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
            background: #0f1117;
            color: #e5e9f0;
            padding: 6px 12px;
            border-radius: 6px;
            border: 1px solid #2a2f3a;
            font-size: 14px;
        }}
        .timestamp {{
            text-align: right;
            color: #6e7b8c;
            font-size: 13px;
            margin-top: 16px;
            font-family: 'SF Mono', 'Fira Code', monospace;
        }}
        .security-note {{
            background: #0f172a;
            border: 1px solid #1e3a5f;
            border-radius: 8px;
            padding: 16px;
            margin-top: 24px;
        }}
        .security-note p {{
            color: #7aa2f7;
            font-size: 13px;
            margin-bottom: 8px;
        }}
        .security-note p:last-child {{
            margin-bottom: 0;
        }}
        .footer {{
            background: #0a0c10;
            padding: 20px 32px;
            border-top: 1px solid #2a2f3a;
            text-align: center;
        }}
        .footer p {{
            color: #6e7b8c;
            font-size: 12px;
            margin: 4px 0;
        }}
        .divider {{
            height: 1px;
            background: #2a2f3a;
            margin: 20px 0;
        }}
    </style>
</head>
<body>
    <div class="email-wrapper">
        <div class="header">
            <div class="header-content">
                <div class="status-icon">✓</div>
                <div class="header-text">
                    <h1>SSH Authentication Success</h1>
                    <span class="badge">Security Event • Authenticated</span>
                </div>
            </div>
        </div>
        
        <div class="content">
            <div class="info-grid">
                <div class="info-row">
                    <span class="info-label">Username</span>
                    <span class="info-value">{user}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Authentication</span>
                    <span class="info-value"><span class="method-tag">{method.upper()}</span></span>
                </div>
                <div class="info-row">
                    <span class="info-label">Source IP</span>
                    <span class="info-value"><span class="ip-block">{ip}</span></span>
                </div>
                <div class="info-row">
                    <span class="info-label">Port</span>
                    <span class="info-value">{port}</span>
                </div>
            </div>
            
            <div class="timestamp">
                {time.strftime('%Y-%m-%d %H:%M:%S UTC')}
            </div>
            
            <div class="security-note">
                <p>🔒 This successful authentication has been logged.</p>
                <p>If you did not initiate this session, please review your security settings immediately.</p>
            </div>
        </div>
        
        <div class="footer">
            <p>SSH Monitor • Security Information & Event Management</p>
            <p>This is an automated alert from your infrastructure monitoring system</p>
        </div>
    </div>
</body>
</html>
    """

# failed login
def build_failed_email(reason, user, ip, port, attempt_count=None):
    attempt_info = f"Attempt #{attempt_count}" if attempt_count else "Authentication Failure"
    
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSH Failure Alert</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background-color: #0a0c10;
            line-height: 1.6;
        }}
        .email-wrapper {{
            max-width: 600px;
            margin: 20px auto;
            background: #0f1117;
            border: 1px solid #2a2f3a;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.5);
        }}
        .header {{
            background: #1a0f12;
            padding: 24px 32px;
            border-bottom: 2px solid #bf4b4b;
        }}
        .header-content {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .status-icon {{
            width: 48px;
            height: 48px;
            background: #bf4b4b;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            color: #ffffff;
        }}
        .header-text {{
            flex: 1;
        }}
        .header-text h1 {{
            color: #e5e9f0;
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 4px;
        }}
        .header-text .badge {{
            color: #ffb4b4;
            font-size: 14px;
            font-weight: 500;
            background: rgba(191, 75, 75, 0.2);
            padding: 4px 12px;
            border-radius: 20px;
            display: inline-block;
        }}
        .content {{
            padding: 32px;
            background: #0f1117;
        }}
        .reason-box {{
            background: #1a1013;
            border: 1px solid #bf4b4b40;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 24px;
        }}
        .reason-box h3 {{
            color: #ffb4b4;
            font-size: 14px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 12px;
        }}
        .reason-box p {{
            color: #e5e9f0;
            font-size: 16px;
            font-weight: 500;
            font-family: 'SF Mono', 'Fira Code', monospace;
            background: #0f1117;
            padding: 12px;
            border-radius: 6px;
            border: 1px solid #2a2f3a;
        }}
        .info-grid {{
            background: #1a1e26;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 24px;
            border: 1px solid #2a2f3a;
        }}
        .info-row {{
            display: flex;
            padding: 12px 0;
            border-bottom: 1px solid #2a2f3a;
        }}
        .info-row:last-child {{
            border-bottom: none;
        }}
        .info-label {{
            width: 140px;
            color: #8b949e;
            font-size: 14px;
            font-weight: 500;
        }}
        .info-value {{
            flex: 1;
            color: #e5e9f0;
            font-size: 15px;
            font-weight: 500;
        }}
        .ip-block {{
            font-family: 'SF Mono', 'Fira Code', monospace;
            background: #0f1117;
            color: #e5e9f0;
            padding: 6px 12px;
            border-radius: 6px;
            border: 1px solid #2a2f3a;
            font-size: 14px;
        }}
        .attempt-counter {{
            background: #1e1a1a;
            border: 1px solid #bf4b4b40;
            border-radius: 20px;
            padding: 8px 16px;
            display: inline-block;
            margin-bottom: 20px;
        }}
        .attempt-counter span {{
            color: #ffb4b4;
            font-size: 13px;
            font-weight: 600;
        }}
        .timestamp {{
            text-align: right;
            color: #6e7b8c;
            font-size: 13px;
            margin-top: 16px;
            font-family: 'SF Mono', 'Fira Code', monospace;
        }}
        .alert-note {{
            background: #1a1013;
            border: 1px solid #bf4b4b;
            border-radius: 8px;
            padding: 16px;
            margin-top: 24px;
        }}
        .alert-note p {{
            color: #ffb4b4;
            font-size: 13px;
            margin-bottom: 8px;
        }}
        .alert-note p:last-child {{
            margin-bottom: 0;
        }}
        .footer {{
            background: #0a0c10;
            padding: 20px 32px;
            border-top: 1px solid #2a2f3a;
            text-align: center;
        }}
        .footer p {{
            color: #6e7b8c;
            font-size: 12px;
            margin: 4px 0;
        }}
    </style>
</head>
<body>
    <div class="email-wrapper">
        <div class="header">
            <div class="header-content">
                <div class="status-icon">✗</div>
                <div class="header-text">
                    <h1>SSH Authentication Failure</h1>
                    <span class="badge">Security Event • Failed Attempt</span>
                </div>
            </div>
        </div>
        
        <div class="content">
            <div class="attempt-counter">
                <span>{attempt_info}</span>
            </div>
            
            <div class="reason-box">
                <h3>Failure Reason</h3>
                <p>{reason}</p>
            </div>
            
            <div class="info-grid">
                <div class="info-row">
                    <span class="info-label">Username</span>
                    <span class="info-value">{user}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Source IP</span>
                    <span class="info-value"><span class="ip-block">{ip}</span></span>
                </div>
                <div class="info-row">
                    <span class="info-label">Port</span>
                    <span class="info-value">{port}</span>
                </div>
            </div>
            
            <div class="timestamp">
                {time.strftime('%Y-%m-%d %H:%M:%S UTC')}
            </div>
            
            <div class="alert-note">
                <p>⚠️ Multiple failed attempts may indicate a brute force attack.</p>
            </div>
        </div>
        
        <div class="footer">
            <p>SSH Monitor</p>
            <p>This is an automated security alert</p>
        </div>
    </div>
</body>
</html>
    """


def build_multiple_failures_email(ip, count, time_window, last_user, last_reason):
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSH Multiple Failures Alert</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background-color: #0a0c10;
            line-height: 1.6;
        }}
        .email-wrapper {{
            max-width: 600px;
            margin: 20px auto;
            background: #0f1117;
            border: 1px solid #2a2f3a;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.5);
        }}
        .header {{
            background: #1f0f0f;
            padding: 24px 32px;
            border-bottom: 2px solid #bf4b4b;
        }}
        .header-content {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .status-icon {{
            width: 48px;
            height: 48px;
            background: #bf4b4b;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            color: #ffffff;
        }}
        .header-text {{
            flex: 1;
        }}
        .header-text h1 {{
            color: #e5e9f0;
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 4px;
        }}
        .header-text .badge {{
            color: #ffb4b4;
            font-size: 14px;
            font-weight: 500;
            background: rgba(191, 75, 75, 0.2);
            padding: 4px 12px;
            border-radius: 20px;
            display: inline-block;
        }}
        .critical-badge {{
            background: #bf4b4b;
            color: #ffffff;
            padding: 8px 16px;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            display: inline-block;
            margin-bottom: 24px;
        }}
        .content {{
            padding: 32px;
            background: #0f1117;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: #1a1e26;
            border: 1px solid #2a2f3a;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        }}
        .stat-number {{
            color: #bf4b4b;
            font-size: 32px;
            font-weight: 700;
            font-family: 'SF Mono', monospace;
            line-height: 1.2;
            margin-bottom: 4px;
        }}
        .stat-label {{
            color: #8b949e;
            font-size: 13px;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .threat-card {{
            background: #1f0f0f;
            border: 1px solid #bf4b4b;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 24px;
        }}
        .threat-card h3 {{
            color: #ffb4b4;
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 12px;
        }}
        .threat-card p {{
            color: #e5e9f0;
            font-size: 14px;
            margin-bottom: 16px;
        }}
        .details-card {{
            background: #1a1e26;
            border: 1px solid #2a2f3a;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 24px;
        }}
        .detail-row {{
            padding: 10px 0;
            border-bottom: 1px solid #2a2f3a;
        }}
        .detail-row:last-child {{
            border-bottom: none;
        }}
        .detail-label {{
            color: #8b949e;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
        }}
        .detail-value {{
            color: #e5e9f0;
            font-size: 15px;
            font-weight: 500;
            font-family: 'SF Mono', monospace;
        }}
        .action-box {{
            background: #0f172a;
            border: 1px solid #1e3a5f;
            border-radius: 10px;
            padding: 20px;
            margin: 24px 0;
        }}
        .action-box h4 {{
            color: #7aa2f7;
            font-size: 14px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 12px;
        }}
        .action-box ul {{
            list-style: none;
            padding: 0;
        }}
        .action-box li {{
            color: #e5e9f0;
            font-size: 14px;
            padding: 6px 0 6px 20px;
            position: relative;
        }}
        .action-box li::before {{
            content: "•";
            color: #bf4b4b;
            font-weight: bold;
            position: absolute;
            left: 0;
        }}
        .timestamp {{
            text-align: right;
            color: #6e7b8c;
            font-size: 13px;
            margin-top: 16px;
            font-family: 'SF Mono', monospace;
        }}
        .footer {{
            background: #0a0c10;
            padding: 20px 32px;
            border-top: 1px solid #2a2f3a;
            text-align: center;
        }}
        .footer p {{
            color: #6e7b8c;
            font-size: 12px;
            margin: 4px 0;
        }}
    </style>
</head>
<body>
    <div class="email-wrapper">
        <div class="header">
            <div class="header-content">
                <div class="status-icon">⚠️</div>
                <div class="header-text">
                    <h1>Critical Security Alert</h1>
                    <span class="badge">HIGH • Multiple Authentication Failures</span>
                </div>
            </div>
        </div>
        
        <div class="content">
            <div class="critical-badge">Potential Brute Force Attack Detected</div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{count}</div>
                    <div class="stat-label">Failed Attempts</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{time_window}s</div>
                    <div class="stat-label">Time Window</div>
                </div>
            </div>
            
            <div class="threat-card">
                <h3>🚨 Threat Assessment</h3>
                <p>Multiple failed SSH authentication attempts detected from a single source IP within a short time window. This pattern is consistent with brute force attack behavior.</p>
            </div>
            
            <div class="details-card">
                <div class="detail-row">
                    <div class="detail-label">Source IP Address</div>
                    <div class="detail-value">{ip}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Last Username Attempted</div>
                    <div class="detail-value">{last_user}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Last Failure Reason</div>
                    <div class="detail-value">{last_reason}</div>
                </div>
            </div>
            
            <div class="action-box">
                <h4>🔴 Recommended Actions</h4>
                <ul>
                    <li>Immediately review authentication logs</li>
                    <li>Consider blocking IP: {ip} at firewall level</li>
                    <li>Check for any successful logins from this IP</li>
                    <li>Review and update fail2ban/jail configurations</li>
                    <li>Audit user accounts for unauthorized access</li>
                </ul>
            </div>
            
            <div class="timestamp">
                {time.strftime('%Y-%m-%d %H:%M:%S UTC')}
            </div>
        </div>
        
        <div class="footer">
            <p>SSH Monitor</p>
        </div>
    </div>
</body>
</html>
    """

class SSHLogHandler(FileSystemEventHandler):
    def __init__(self):
        # start reading from the end of file
        with open(AUTH_LOG, "r") as f:
            f.seek(0, 2) 
            self.last_size = f.tell()

    def on_modified(self, event):
        if event.src_path == AUTH_LOG:
            with open(AUTH_LOG, "r") as f:
                f.seek(self.last_size)
                new_lines = f.readlines()
                self.last_size = f.tell()
                for line in new_lines:
                    self.parse_line(line.strip())

    def parse_line(self, line):
        current_time = time.time()

        # SESSION CLOSE 
        close_match = CLOSE_REGEX.search(line)
        if close_match:
            _, ip, port = close_match.groups()
            session_key = f"{ip}:{port}"
            active_sessions.discard(session_key)
            failed_attempts.pop(ip, None)  
            return

        # SUCCESS LOGIN 
        success_match = SUCCESS_REGEX.search(line)
        if success_match:
            method, user, ip, port = success_match.groups()
            session_key = f"{ip}:{port}"
            active_sessions.add(session_key)

            # Clear failed attempts after a successful login
            failed_attempts.pop(ip, None)

            html_body = build_success_email(user, ip, port, method)
            send_email("SSH: Successful Login Detected", html_body, is_html=True)
            return

        # FAILED LOGIN
        fail_match = FAIL_REGEX.search(line)
        if fail_match:
            reason, user, ip, port = fail_match.groups()
            session_key = f"{ip}:{port}"
            active_sessions.add(session_key)

            # Track failed attempts for aggregation
            attempts = failed_attempts.get(ip, [])
            # Remove old attempts outside time window
            attempts = [t for t in attempts if current_time - t <= TIME_WINDOW]
            attempts.append(current_time)
            failed_attempts[ip] = attempts

            # send individual failed login alert with styled HTML
            html_body = build_failed_email(reason, user, ip, port, len(attempts))
            send_email(f"SSH: Failed Login from {ip}", html_body, is_html=True)

            # send threshold alert if reached exactly at threshold
            if len(attempts) == FAIL_THRESHOLD:
                html_body = build_multiple_failures_email(ip, FAIL_THRESHOLD, TIME_WINDOW, user, reason)
                send_email(f"🚨 CRITICAL: Multiple SSH Failures from {ip}", html_body, is_html=True)
            return

if __name__ == "__main__":
    # SSH log watcher 
    event_handler = SSHLogHandler()
    observer = Observer()
    observer.schedule(event_handler, path=AUTH_LOG, recursive=False)
    observer.start()

    # Config watcher 
    class ConfigHandler(FileSystemEventHandler):
        def on_modified(self, event):
            if event.src_path == CONFIG_FILE:
                print("⚡ Config file changed. Restarting ssh-monitor service...")
                # Restart the systemd service
                import subprocess
                subprocess.run(["sudo", "systemctl", "restart", "ssh-monitor.service"])

    config_observer = Observer()
    config_observer.schedule(ConfigHandler(), path=os.path.dirname(CONFIG_FILE), recursive=False)
    config_observer.start()

    print("🔒 SSH Monitor Running… Watching for login events.")
    print(f"📊 Alert threshold: {FAIL_THRESHOLD} failures in {TIME_WINDOW} seconds")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        config_observer.stop()

    observer.join()
    config_observer.join()