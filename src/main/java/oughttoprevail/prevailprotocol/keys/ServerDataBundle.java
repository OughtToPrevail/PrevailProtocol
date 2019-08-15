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

import java.util.Collections;
import java.util.List;
import java.util.Queue;

import oughttoprevail.prevailprotocol.storage.Storage;
import oughttoprevail.prevailprotocol.storage.fields.Field;
import oughttoprevail.prevailprotocol.uid.UID;

/**
 * A {@link ServerDataBundle} contains all public information of user's {@link DataBundle}.
 */
public class ServerDataBundle
{
	private final UID deviceId;
	private final Field<byte[]> identityKey;
	private final Field<IdentifiableKey> signedPreKey;
	private final Field<byte[]> preKeySignature;
	private final Queue<IdentifiableKey> oneTimePreKeys;
	private final Storage deviceStorage;
	
	public ServerDataBundle(UID deviceId,
							Field<byte[]> identityKey,
							Field<IdentifiableKey> signedPreKey,
							Field<byte[]> preKeySignature,
							Queue<IdentifiableKey> oneTimePreKeys,
							Storage deviceStorage)
	{
		this.deviceId = deviceId;
		this.identityKey = identityKey;
		this.signedPreKey = signedPreKey;
		this.preKeySignature = preKeySignature;
		this.oneTimePreKeys = oneTimePreKeys;
		this.deviceStorage = deviceStorage;
	}
	
	public void init(byte[] identityKey, IdentifiableKey signedPreKey, byte[] preKeySignature, IdentifiableKey[] oneTimePreKeys)
	{
		this.identityKey.set(identityKey);
		this.signedPreKey.set(signedPreKey);
		this.preKeySignature.set(preKeySignature);
		Collections.addAll(this.oneTimePreKeys, oneTimePreKeys);
		deviceStorage.flush();
	}
	
	public UID getDeviceId()
	{
		return deviceId;
	}
	
	public byte[] getIdentityKey()
	{
		return identityKey.get();
	}
	
	public IdentifiableKey getSignedPreKey()
	{
		return signedPreKey.get();
	}
	
	public byte[] getPreKeySignature()
	{
		return preKeySignature.get();
	}
	
	public void changeSignedPreKey(byte[] signedPreKey, UID signedPreKeyUID, byte[] preKeySignature)
	{
		this.signedPreKey.set(new IdentifiableKey(signedPreKeyUID, signedPreKey));
		this.preKeySignature.set(preKeySignature);
		deviceStorage.flush();
	}
	
	public void addOneTimePreKeys(List<IdentifiableKey> oneTimePreKeys)
	{
		this.oneTimePreKeys.addAll(oneTimePreKeys);
		deviceStorage.flush();
	}
	
	public IdentifiableKey pickOneTimePreKey()
	{
		if(oneTimePreKeys.isEmpty())
		{
			return null;
		}
		IdentifiableKey identifiableKey = oneTimePreKeys.poll();
		deviceStorage.flush();
		return identifiableKey;
	}
	
	public int getTotalOneTimePreKeys()
	{
		return oneTimePreKeys.size();
	}
}