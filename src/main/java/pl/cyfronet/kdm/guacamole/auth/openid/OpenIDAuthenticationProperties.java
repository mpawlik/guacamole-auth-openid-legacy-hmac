package pl.cyfronet.kdm.guacamole.auth.openid;

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
}
