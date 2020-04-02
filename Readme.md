# Setting up Guacamole

**Author**:  _quiet_

### Download - [Debian 9 Stretch](https://cdimage.debian.org/cdimage/archive/9.9.0/amd64/iso-cd/debian-9.9.0-amd64-netinst.iso)
It's a known good setup for guac. When I upgraded to Buster, I had problems.

### Login as your root user. For some reason, my debian lxc containers don't include sudo by default.. so.
```
root@guac:# apt install sudo
root@guac:# adduser remotegod
root@guac:# usermod -aG sudo remotegod
root@guac:# logout
```

# Now log in as the user you created. Update all teh things.
```
remotegod@guac:$ sudo apt update && sudo apt upgrade
remotegod@guac:$ wget https://raw.githubusercontent.com/MysticRyuujin/guac-install/master/guac-install.sh
remotegod@guac:$ chmod +x guac-install.sh
remotegod@guac:$ sudo ./guac-install --mysqlpwd password --guacpwd password
```

### So, now that Guacamole is installed.. it comes with two factor enabled by default.. which would be cool in any other circumstance right?

-- Yeah.. so we gotta deal with that.
```
remotegod@guac:$ rm -rf /etc/guacamole/extensions/guacamole-auth-totp-1.0.0.jar
```

###  Now let's setup our proxy
```
remotegod@guac:$ sudo apt install nginx certbot python-certbot-nginx apache2-utils
```

### Replace $USERNAME with a username of your choice, then it'll prompt you for a password.
```
remotegod@guac:$ sudo htpasswd -c /etc/nginx/.htpasswd $USERNAME
```

### Now let's setup our nginx guac config
```
remotegod@guac:$ sudo nano /etc/nginx/sites-available/guac
```

### Nginx Configuration for Guacamole
-- `$CODENAME` = subdomain, if you setup your domain/network that way.
-- `$DOMAIN` = domain that you purchased. 
```
server {
    # Initial configuration
      server_name $CODENAME.$DOMAIN.com;
      #add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
      #add_header X-Frame-Options DENY always;
      #add_header X-Content-Type-Options nosniff always;
      #add_header X-Xss-Protection "1; mode=block" always;
      location / {
           proxy_pass http://$GUACIP:8080/guacamole/;
           proxy_buffering off;
           proxy_http_version 1.1;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection $http_connection;
           #allow 10.0.0.0/24; # Local LAN
           #allow 137.242.1.0/24; # AFNET
           auth_basic "Authorized Users Only!"; # Will prompt you for a username and password before you're always to get to this location.
           auth_basic_user_file /etc/nginx/.htpasswd; # passwd file for authentication
           #deny all; # If you're not accessing guac from home or NIPR, deny.
        }
    listen 80; # We'll setup our redirect after we have certs
}
```

### Cool, assuming your portforwarding is setup correctly on your router, now we're good to get certs.
```
remotegod@guac:$ sudo nginx -t
remotegod@guac:$ sudo ln -s /etc/nginx/sites-available/guac /etc/nginx/sites-enabled/
remotegod@guac:$ sudo systemctl reload nginx
remotegod@guac:$ sudo certbot --nginx
```

-- Follow the prompts, and ask it to auto redirect...DONE!

### Couple more edits/hardening.

-- Change your nginx config to look something like this now..
```
remotegod@guac:$ sudo nano /etc/nginx/sites-available/guac
```
```
server {
        # SSL configuration
        server_name $CODENAME.$DOMAIN.com;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-Frame-Options DENY always;
        add_header X-Content-Type-Options nosniff always;
        add_header X-Xss-Protection "1; mode=block" always;
        location / {
                proxy_pass http://$GUACIP:8080/guacamole/;
                proxy_buffering off;
                proxy_http_version 1.1;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header Upgrade $http_upgrade;
                proxy_set_header Connection $http_connection;
                allow 10.0.0.0/24; # Local LAN
                allow 137.242.1.0/24; # AFNET
                auth_basic "Authorized Users Only!";
                auth_basic_user_file /etc/nginx/.htpasswd;
                deny all;
        }

    listen 443 ssl; # managed by Certbot
    ssl_certificate /etc/letsencrypt/live/$CODENAME.$DOMAIN.com/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/$CODENAME.$DOMAIN.com/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot
}


server {
    if ($host = $CODENAME.$DOMAIN.com) {
        return 301 https://$host$request_uri;
    } # managed by Certbot
    listen 80;
    server_name $CODENAME.$DOMAIN.com;
    return 404; # managed by Certbot
}
```

### There are some nginx defaults to change as well.
-- Honestly, anything that's commented.. I'd just delete.
```
remotegod@guac:$ sudo nano /etc/nginx/nginx.conf
```
```
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
        worker_connections 768;
        # multi_accept on;
}

http {

        ##
        # Basic Settings
        ##

        sendfile on;
        tcp_nopush on;
        tcp_nodelay on;
        keepalive_timeout 65;
        types_hash_max_size 2048;
        server_tokens off;   <---------- Change this to off

        # server_names_hash_bucket_size 64;
        # server_name_in_redirect off;

        include /etc/nginx/mime.types;
        default_type application/octet-stream;

        ##
        # SSL Settings
        ##

        ssl_protocols TLSv1.2; # Dropping SSLv3, ref: POODLE
        ssl_prefer_server_ciphers on;

        ##
        # Logging Settings
        ##

        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;

        ##
        # Gzip Settings
        ##

        gzip on;

        # gzip_vary on;
        # gzip_proxied any;
        # gzip_comp_level 6;
        # gzip_buffers 16 8k;
        # gzip_http_version 1.1;
        # gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

        ##
        # Virtual Host Configs
        ##

        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/*;
}

#mail { <----------------- delete this whole block.
#       # See sample authentication script at:
#       # http://wiki.nginx.org/ImapAuthenticateWithApachePhpScript
#
#       # auth_http localhost/auth.php;
#       # pop3_capabilities "TOP" "USER";
#       # imap_capabilities "IMAP4rev1" "UIDPLUS";
#
#       server {
#               listen     localhost:110;
#               protocol   pop3;
#               proxy      on;
#       }
#
#       server {
#               listen     localhost:143;
#               protocol   imap;
#               proxy      on;
#       }
#}
```

### Next we need to remove weak SSL ciphers. You can just delete everything from that file and add the content below.
```
remotegod@guac:$ sudo nano /etc/letsencrypt/options-ssl-nginx.conf
```

-- This file contains important security parameters. If you modify this file manually, Certbot will be unable to automatically provide future security updates. Instead, Certbot will print and log an error message with a path to the up-to-date file that you will need to refer to when manually updating this file.

```
ssl_stapling on;
ssl_stapling_verify on;

ssl_session_cache shared:le_nginx_SSL:1m;
ssl_session_timeout 10m;

ssl_protocols TLSv1.2;
ssl_prefer_server_ciphers on;

ssl_ciphers "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:!DSS";
```

### Okay, that pretty much covers it. Make sure we didn't make any mistakes..
```
remotegod@guac:$ sudo nginx -t
remotegod@guac:$ sudo systemctl reload nginx
```
DONE!!
