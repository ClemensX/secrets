package de.fehrprice.secrets.entity;

import java.util.List;

import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.NamedQuery;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.TypedQuery;

@Entity
@Table(name = "config")
public class Config {
	@Id
	private int id;
	private int numSlots;

	public int getId() {
		return id;
	}
	public void setId(int id) {
		this.id = id;
	}
	public int getNumSlots() {
		return numSlots;
	}
	public void setNumSlots(int numSlots) {
		this.numSlots = numSlots;
	}


}
