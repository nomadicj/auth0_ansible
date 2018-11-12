## S3 Upload
Upload `infra/ansible/auth0-json/s3` folder to S3. This S3 URL will be used to replace `__S3_URL__` variable inside HTML files

## Management endpoints:

### Tenants
* Error Page: __PATCH__ `/api/v2/tenants/settings`: `patch-error-page.json`
    * Replace attributes
        * url: `http://ci.uam-c.preprod-wyfl.allianzuk.cloud.s3-website.eu-central-1.amazonaws.com/error`
* Password Reset Hosted Page: __PATCH__ `/api/v2/tenants/settings`: `patch-password-reset-page.json`
    * Replace `@@password-reset.html@@` in the JSON with the escaped content of `password-reset.html`

### Clients
* UAM-C Application: __POST__ `/api/v2/clients`: `post-uamc-application.json`
    * Replace attributes:
        * Replace `__APP_URL__` with the Application URL (ie: _`http://localhost:8081`_)
* Login Hosted Page: __PATCH__ + __client_id__ of `All Applications` client `/api/v2/clients/{id}`: `patch-login-page.json`
    * Replace `@@login.html@@` in the JSON with the escaped content of `login.html`

### Email Provider
* Configure: __POST__ `/api/v2/emails/provider`: `post-email-provider.json`
    * Replace attributes
        * smtp_host
        * smtp_port
        * smtp_user
        * smtp_pass

### Email Template (Requires Email Provider)
* Verification: __POST__ `/api/v2/email-templates`: `post-verification.json`
    * Replace attributes
        * from
        * resultUrl: `http://ci.uam-c.preprod-wyfl.allianzuk.cloud.s3-website.eu-central-1.amazonaws.com/home`
        * Replace `@@post-verification.html@@` in the JSON with the escaped content of `post-verification.html`
* Change password: __POST__ `/api/v2/email-templates`: `post-change-password.json`
    * Replace attributes
        * resultUrl
        * Replace `@@post-change-password.html@@` in the JSON with the escaped content of `post-change-password.html`