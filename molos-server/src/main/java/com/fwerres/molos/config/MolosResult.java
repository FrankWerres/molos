package com.fwerres.molos.config;

import java.util.ArrayList;
import java.util.List;

public class MolosResult {

	private boolean success = false;
	private List<String> messages = new ArrayList<>();
	
	public boolean isSuccess() {
		return success;
	}
	
	public void setSuccess(boolean success) {
		this.success = success;
	}
	
	public List<String> getMessages() {
		return messages;
	}
	
	public void addToMessages(String msg) {
		messages.add(msg);
	}
}
