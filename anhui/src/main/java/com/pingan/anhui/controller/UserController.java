package com.pingan.anhui.controller;

import java.util.Date;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import com.pingan.anhui.dto.User;

@Controller
public class UserController {
	
	@RequestMapping("/user")
	public ResponseEntity<User> getUser(){
		
		User user = new User();
		user.setAge(22);
		user.setBirthday(new Date());
		user.setName("nancy");
		user.setPassword("13123");
		
		return ResponseEntity.ok(user);
	}
	
	@RequestMapping("/user2")
	public ResponseEntity<User> exex(){
		
		User user = new User();
		user.setAge(12);
		user.setBirthday(new Date());
		user.setName("lisa");
		user.setPassword("1224111");
		
		return ResponseEntity.ok(user);
	}

}
