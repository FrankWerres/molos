package com.fwerres.sample.webservice.impl;

import com.fwerres.sample.webservice.ObjectFactory;
import com.fwerres.sample.webservice.WebService;

import jakarta.jws.HandlerChain;
import jakarta.jws.WebMethod;
import jakarta.jws.WebParam;
import jakarta.jws.WebResult;
import jakarta.xml.bind.annotation.XmlSeeAlso;
import jakarta.xml.ws.RequestWrapper;
import jakarta.xml.ws.ResponseWrapper;

@jakarta.jws.WebService(
		name = "WebService", 
		serviceName = "WebService", 
		portName = "WebServiceSOAP", 
		targetNamespace = "http://www.example.org/WebService/")
@HandlerChain(file = "jwt_handler.xml")
@XmlSeeAlso({
    ObjectFactory.class
})
public class WebServiceImpl implements WebService {

	@Override
	@WebMethod(operationName = "NewOperation", action = "http://www.example.org/WebService/NewOperation")
    @WebResult(name = "out", targetNamespace = "")
    @RequestWrapper(localName = "NewOperation", targetNamespace = "http://www.example.org/WebService/", className = "com.fwerres.sample.webservice.NewOperation")
    @ResponseWrapper(localName = "NewOperationResponse", targetNamespace = "http://www.example.org/WebService/", className = "com.fwerres.sample.webservice.NewOperationResponse")
    public String newOperation(
        @WebParam(name = "in", targetNamespace = "")
        String in) {
		return "Processed by newOperation: " + in;
	}

}
