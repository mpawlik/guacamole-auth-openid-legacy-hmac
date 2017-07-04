package pl.cyfronet.kdm.guacamole.auth.openid;

import org.apache.guacamole.properties.IntegerGuacamoleProperty;
import org.apache.guacamole.properties.StringGuacamoleProperty;

public class OpenIDAuthenticationProperties {
    public OpenIDAuthenticationProperties() {
    }

    public static final StringGuacamoleProperty OPENID_ENDPOINT = new StringGuacamoleProperty() {
        public String getName() {
            return "openid-legacy-endpoint";
        }
    };

    public static final StringGuacamoleProperty OPENID_RETURNTOURL = new StringGuacamoleProperty() {
        public String getName() {
            return "openid-legacy-returntourl";
        }
    };

    public static final StringGuacamoleProperty OPENID_REALM = new StringGuacamoleProperty() {
        public String getName() {
            return "openid-legacy-realm";
        }
    };

    public static final StringGuacamoleProperty SECRET_KEY = new StringGuacamoleProperty() {
        public String getName() {
            return "openid-legacy-secret-key";
        }
    };

    public static final StringGuacamoleProperty DEFAULT_PROTOCOL = new StringGuacamoleProperty() {
        public String getName() {
            return "openid-legacy-default-protocol";
        }
    };

    public static final IntegerGuacamoleProperty TIMESTAMP_AGE_LIMIT = new IntegerGuacamoleProperty() {
        public String getName() {
            return "openid-legacy-timestamp-age-limit";
        }
    };
}
