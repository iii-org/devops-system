import smtplib
from email.mime.text import MIMEText
from resources import apiError
from resources import logger
from model import db, SystemParameter

class Mail:
    def __init__(self):
        self.__get_account_and_password()
        self.__init_mail_server()

    def __get_account_and_password(self):        
        self.smtp_server, self.smtp_server_port, self.smtp_server_account, \
        self.smtp_server_password = get_basic_mail_info()

    @staticmethod
    def check_mail_server(domain=None, port=None, account=None, password=None):
        smtp_server, smtp_server_port, smtp_server_account, \
        smtp_server_password = get_basic_mail_info()
        domain = domain or smtp_server
        port = port or smtp_server_port
        account = account or smtp_server_account
        password = password or smtp_server_password
        server = None

        try:
            server = smtplib.SMTP(domain, port, timeout=5)
        except Exception as e:
            logger.logger.exception(str(e))
            raise apiError.DevOpsError(404, "Connection refused, port or server are incorrect.",
                        error=apiError.login_email_error())

        server.starttls()
        try:
            server.login(account, password)
        except smtplib.SMTPAuthenticationError as err:
            logger.logger.exception(str(err))
            if domain.endswith("gmail.com"):
                raise apiError.DevOpsError(404, 'Account needs to apply apppassord to login.',
                          error=apiError.gmail_need_apply_apppassword(account))
            raise apiError.DevOpsError(404, 'SMTP auth error',
                          error=apiError.login_email_error())
        except Exception as e:
            logger.logger.exception(str(e))
            raise apiError.DevOpsError(404, 'Account or password are incorrect',
                          error=apiError.login_email_error())

        return server
                            
    def __init_mail_server(self):
        try:
            self.server = self.check_mail_server()
        except:
            self.server = None

    def send_email(self, receiver, title, message):
        text = MIMEText(message, 'plain', 'utf-8')
        text['Subject'] = title
        text['From'] = self.smtp_server_account
        text['To'] = receiver
        text['Disposition-Notification-To'] = self.smtp_server_account

        if self.server is not None:
            self.server.sendmail(self.smtp_server_account, receiver, text.as_string())
            self.server.quit()


def get_basic_mail_info():
    from resources.redmine import get_mail_config
    mail_config = get_mail_config().get("smtp_settings", {})
    smtp_server = mail_config.get("domain")
    smtp_server_port = mail_config.get("port")
    smtp_server_account = mail_config.get("user_name")
    smtp_server_password = mail_config.get("password")
    
    return smtp_server, smtp_server_port, smtp_server_account, smtp_server_password


def mail_server_is_open():
    mail_config = SystemParameter.query.filter_by(name="mail_config").first()
    return mail_config is not None and mail_config.active
    
