package com.operator.service;

import com.operator.bean.User;
import com.operator.common.ServiceResponse;

public interface IUserService {
	
	ServiceResponse<User> login(String username, String password);

    ServiceResponse<String> register(User user);

}
