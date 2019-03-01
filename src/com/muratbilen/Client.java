package com.muratbilen;

public class Client
{
	private String name;
	private String lastname;
	private String idNumber;
	private double amount;

	public Client(String name, String lastname, String idNumber, double amount)
	{
		this.name = name;
		this.lastname = lastname;
		this.idNumber = idNumber;
		this.amount = amount;
	}

	public String getName()
	{
		return name;
	}

	public void setName(String name)
	{
		this.name = name;
	}

	public String getLastname()
	{
		return lastname;
	}

	public void setLastname(String lastname)
	{
		this.lastname = lastname;
	}

	public String getIdNumber()
	{
		return idNumber;
	}

	public void setIdNumber(String idNumber)
	{
		this.idNumber = idNumber;
	}

	public double getAmount()
	{
		return amount;
	}

	public void setAmount(double amount)
	{
		this.amount = amount;
	}
}
