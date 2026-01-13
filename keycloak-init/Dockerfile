FROM alpine:3.19

LABEL maintainer="TechCorp Security Team"
LABEL description="Keycloak User Initialization Container"

# Install curl and bash
RUN apk add --no-cache curl bash

# Copy init script
COPY init-users.sh /init-users.sh
RUN chmod +x /init-users.sh

# Run the init script
CMD ["/init-users.sh"]
