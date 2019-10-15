package cn.com.cloud.account.sso.model;

import lombok.Data;

import java.io.Serializable;

/**
 * @author twg
 * @since 2019/10/15
 */
@Data
public class User implements Serializable {
    private String username;

    public User(String name) {
        this.username = name;
    }
}
