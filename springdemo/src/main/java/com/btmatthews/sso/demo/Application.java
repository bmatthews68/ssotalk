package com.btmatthews.sso.demo;

import com.btmatthews.springboot.memcached.EnableMemcached;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@EnableMemcached
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
