package pl.cyfronet.kdm.guacamole.auth.openid;

import org.glyptodon.guacamole.properties.StringGuacamoleProperty;

public class OpenIDAuthenticationProperties {
    public OpenIDAuthenticationProperties() {
    }

    public static final StringGuacamoleProperty OPENID_ENDPOINT = new StringGuacamoleProperty() {
        public String getName() {
            return "openid-endpoint";
        }
    };

    public static final StringGuacamoleProperty OPENID_RETURNTOURL = new StringGuacamoleProperty() {
        public String getName() {
            return "openid-returntourl";
        }
    };
}
