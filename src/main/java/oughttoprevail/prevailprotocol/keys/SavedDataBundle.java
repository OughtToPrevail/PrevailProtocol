/*
PrevailProtocol.
Copyright (C) 2019  https://github.com/OughtToPrevail

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
package oughttoprevail.prevailprotocol.keys;

import java.util.Iterator;
import java.util.List;

import oughttoprevail.prevailprotocol.storage.Storage;
import oughttoprevail.prevailprotocol.storage.fields.Field;
import oughttoprevail.prevailprotocol.uid.UID;

/**
 * A {@link SavedDataBundle} contains all information needed to create sessions while removing most of the public information which instead of being
 * stored here is stored in the remote {@link ServerDataBundle}.
 */
public class SavedDataBundle
{
	private final Storage storage;
	private final Field<IdentifiableKeyPair> identityKey;
	private final Object signedPreKeyLock = new Object();
	private final Field<SignedPreKey> signedPreKey;
	private final Field<IdentifiableKeyPair> oldSignedPreKey;
	private final List<IdentifiableKey> oneTimePreKeys;
	
	public SavedDataBundle(Storage storage)
	{
		this.storage = storage;
		identityKey = storage.getField(IdentifiableKeyPair.SER_DES);
		signedPreKey = storage.getField(SignedPreKey.SER_DES);
		oldSignedPreKey = storage.getField(IdentifiableKeyPair.SER_DES);
		oneTimePreKeys = storage.getFieldList(IdentifiableKey.SER_DES);
	}
	
	public void init(DataBundle dataBundle)
	{
		identityKey.set(dataBundle.getIdentityKeys());
		signedPreKey.set(dataBundle.getSignedPreKey());
		oldSignedPreKey.set(null);
		for(IdentifiableKeyPair oneTimePreKey : dataBundle.getOneTimePreKeys())
		{
			oneTimePreKeys.add(new IdentifiableKey(oneTimePreKey.getUID(), oneTimePreKey.getPrivateKey()));
		}
	}
	
	public IdentifiableKeyPair getIdentityKey()
	{
		return identityKey.get();
	}
	
	public SignedPreKey getSignedPreKey()
	{
		synchronized(signedPreKeyLock)
		{
			return signedPreKey.get();
		}
	}
	
	public void changeSignedPreKey(SignedPreKey signedPreKey)
	{
		synchronized(signedPreKeyLock)
		{
			this.oldSignedPreKey.set(this.signedPreKey.get());
			this.signedPreKey.set(signedPreKey);
			storage.flush();
		}
	}
	
	public IdentifiableKeyPair findSignedPreKey(UID signedPreKeyUID)
	{
		synchronized(signedPreKeyLock)
		{
			if(signedPreKey.get().getUID().equals(signedPreKeyUID))
			{
				return getSignedPreKey();
			} else if(oldSignedPreKey.get() != null && oldSignedPreKey.get().getUID().equals(signedPreKeyUID))
			{
				return oldSignedPreKey.get();
			}
		}
		return null;
	}
	
	public IdentifiableKey removeOneTimePreKey(UID oneTimePreKeyUID)
	{
		Iterator<IdentifiableKey> iterator = oneTimePreKeys.iterator();
		while(iterator.hasNext())
		{
			IdentifiableKey identifiableKey = iterator.next();
			if(identifiableKey.getUID().equals(oneTimePreKeyUID))
			{
				iterator.remove();
				storage.flush();
				return identifiableKey;
			}
		}
		return null;
	}
}