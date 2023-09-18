package org.miniorange.saml;


import java.io.Serializable;
import java.util.Map;

public class MoSAMLResponse implements Serializable {
    private static final long serialVersionUID = 1L;
    private Map<String, String[]> attributes;
    private String nameId;
    private String sessionIndex;
    private String inResponseTo;

    public MoSAMLResponse(Map<String, String[]> attributes, String nameId, String sessionIndex, String inResponseTo) {
        this.attributes = attributes;
        this.nameId = nameId;
        this.sessionIndex = sessionIndex;
        this.inResponseTo = inResponseTo;
    }

    public Map<String, String[]> getAttributes() {
        return this.attributes;
    }

    public void setAttributes(Map<String, String[]> attributes) {
        this.attributes = attributes;
    }

    public String getInResponseTo() {
        return inResponseTo;
    }

    @Override
    public String toString() {
        return "MoSAMLResponse{attributes=" + this.attributes + ", nameId=" + this.nameId + ", sessionIndex='" + this.sessionIndex + "}";
    }
}

