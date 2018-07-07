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

}
