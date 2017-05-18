package com.operator.service.impl;

import org.springframework.stereotype.Service;

import com.operator.bean.User;
import com.operator.common.ServiceResponse;
import com.operator.service.IUserService;

@Service("iUserService")
public class UserServiceImpl implements IUserService{

	@Override
	public ServiceResponse<User> login(String username, String password) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public ServiceResponse<String> register(User user) {
		// TODO Auto-generated method stub
		return null;
	}

}
