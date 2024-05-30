package com.fwerres.molos.config;

public class SaveBehaviour {

	private boolean saveActionProtocol;
	private boolean saveConfigOnChange;
	private boolean saveConfigHistory;
	
	public boolean isSaveActionProtocol() {
		return saveActionProtocol;
	}
	public void setSaveActionProtocol(boolean saveActionProtocol) {
		this.saveActionProtocol = saveActionProtocol;
	}
	public boolean isSaveConfigOnChange() {
		return saveConfigOnChange;
	}
	public void setSaveConfigOnChange(boolean saveConfigOnChange) {
		this.saveConfigOnChange = saveConfigOnChange;
	}
	public boolean isSaveConfigHistory() {
		return saveConfigHistory;
	}
	public void setSaveConfigHistory(boolean saveConfigHistory) {
		this.saveConfigHistory = saveConfigHistory;
	}
	
}
