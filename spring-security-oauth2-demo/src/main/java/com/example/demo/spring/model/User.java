package com.example.demo.spring.model;

import lombok.Data;

import java.io.Serializable;

/**
 * @author twg
 * @since 2019/8/20
 */
@Data
public class User implements Serializable {
    private String username;

    public User(String username){
        this.username = username;
    }
}
