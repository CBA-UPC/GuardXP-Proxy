# GuardXP Proxy

HTTP/HTTPS tracker blocking based on mitmproxy + ASTrack clean resources

## Setup

1. Create base folder for certificates and geolocation DB:
   ```bash
   mkdir -p ~/.guardxp-px/geoip2_db
   cd ~/.guardxp-px
   wget https://github.com/FyraLabs/geolite2/releases/download/1738783496/GeoLite2-Country.mmdb -P ./geoip2_db
   ```

2. Clone the repository:
   ```bash
   git clone https://github.com/ismael-castell/GuardXP.git
   cd guardxp
   ```

3. Start the application:
   ```bash
   docker-compose up --build
   ```

## Prerequisites

- Docker and Docker Compose installed
- Internet connection for downloading the GeoLite2 database

## Notes

- The GeoLite2 database is used for geolocation services
- Certificates are automatically generated in the `.guardxp-px` directory
- For production deployments, additional configuration may be required


