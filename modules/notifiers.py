import json
import logging
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from abc import ABC, abstractmethod

log = logging.getLogger("RECON.Notifiers")

class Notifier(ABC):
    @abstractmethod
    def send(self, target, subject, message):
        pass

class SlackNotifier(Notifier):
    def __init__(self, webhook_url):
        self.webhook_url = webhook_url

    def send(self, target, subject, message):
        if not self.webhook_url: return
        payload = {
            "text": f"*{subject}*\nTarget: `{target}`\n\n{message}"
        }
        try:
            requests.post(self.webhook_url, json=payload, timeout=10)
            log.info("Slack notification sent.")
        except Exception as e:
            log.error(f"Slack notification failed: {e}")

class DiscordNotifier(Notifier):
    def __init__(self, webhook_url):
        self.webhook_url = webhook_url

    def send(self, target, subject, message):
        if not self.webhook_url: return
        payload = {
            "content": f"**{subject}**\nTarget: `{target}`\n\n{message}"
        }
        try:
            requests.post(self.webhook_url, json=payload, timeout=10)
            log.info("Discord notification sent.")
        except Exception as e:
            log.error(f"Discord notification failed: {e}")

class EmailNotifier(Notifier):
    def __init__(self, smtp_server, smtp_port, smtp_user, smtp_pass, recipient):
        self.config = {
            'server': smtp_server,
            'port': smtp_port,
            'user': smtp_user,
            'pass': smtp_pass,
            'to': recipient
        }

    def send(self, target, subject, message):
        if not all([self.config['server'], self.config['user'], self.config['to']]):
            return
        
        msg = MIMEMultipart()
        msg['From'] = self.config['user']
        msg['To'] = self.config['to']
        msg['Subject'] = f"{subject} - {target}"
        msg.attach(MIMEText(message, 'plain'))
        
        try:
            with smtplib.SMTP(self.config['server'], int(self.config['port'])) as server:
                server.starttls()
                server.login(self.config['user'], self.config['pass'])
                server.send_message(msg)
            log.info("Email notification sent.")
        except Exception as e:
            log.error(f"Email notification failed: {e}")

class NotificationManager:
    def __init__(self, enabled_notifiers=None):
        self.notifiers = []
        if not enabled_notifiers: return
        
        import os
        if 'slack' in enabled_notifiers:
            self.notifiers.append(SlackNotifier(os.getenv('SLACK_WEBHOOK_URL')))
        if 'discord' in enabled_notifiers:
            self.notifiers.append(DiscordNotifier(os.getenv('DISCORD_WEBHOOK_URL')))
        if 'email' in enabled_notifiers:
            self.notifiers.append(EmailNotifier(
                os.getenv('SMTP_SERVER'),
                os.getenv('SMTP_PORT', 587),
                os.getenv('SMTP_USER'),
                os.getenv('SMTP_PASS'),
                os.getenv('NOTIFICATION_EMAIL')
            ))

    def notify_scan_complete(self, target, ports_count, vuln_count, has_changes):
        subject = "🛡️ Recon Scan Complete"
        change_text = "⚠️ CHANGES DETECTED!" if has_changes else "No changes since last scan."
        message = f"Found {ports_count} open ports and {vuln_count} services with vulnerabilities.\n{change_text}"
        
        for n in self.notifiers:
            n.send(target, subject, message)
