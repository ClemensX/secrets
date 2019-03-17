package de.fehrprice.secrets.entity;

import java.io.Serializable;

import javax.persistence.Embeddable;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;

@Embeddable
public class SnippetId implements Serializable {
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	public Long snippedid;
	public Long userid;

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((snippedid == null) ? 0 : snippedid.hashCode());
		result = prime * result + ((userid == null) ? 0 : userid.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		SnippetId other = (SnippetId) obj;
		if (snippedid == null) {
			if (other.snippedid != null)
				return false;
		} else if (!snippedid.equals(other.snippedid))
			return false;
		if (userid == null) {
			if (other.userid != null)
				return false;
		} else if (!userid.equals(other.userid))
			return false;
		return true;
	}
}
