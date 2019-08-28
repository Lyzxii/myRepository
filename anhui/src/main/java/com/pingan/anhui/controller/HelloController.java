package com.pingan.anhui.controller;

import com.pingan.anhui.dto.RequestData;
import com.pingan.anhui.dto.User;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
public class HelloController {
	
	@RequestMapping(value = "/hello",method = RequestMethod.POST)
	public ResponseEntity getHello(@RequestParam("flag") boolean flag, @RequestBody RequestData requestData) {

		if(flag){
			Map data =(HashMap) requestData.getData();
			System.out.println(data);
			return ResponseEntity.ok(data);
		}else{
			List<Map> data =(List<Map>) requestData.getData();
			System.out.println(data.get(1));
			return ResponseEntity.ok(data);
		}

		
	}
}
