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

import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.fields.FieldInputStream;
import oughttoprevail.prevailprotocol.storage.fields.FieldOutputStream;
import oughttoprevail.prevailprotocol.storage.fields.SerDes;
import oughttoprevail.prevailprotocol.uid.UID;

/**
 * An {@link IdentifiableKey} is a {@code byte[]} key with an associated {@link UID} identifier.
 */
public class IdentifiableKey
{
	public static final SerDes<IdentifiableKey> SER_DES = new SerDes<IdentifiableKey>()
	{
		@Override
		public void serialize(IdentifiableKey identifiableKey, FieldOutputStream out, Settings settings)
		{
			out.writeObject(identifiableKey.getUID(), settings.getUIDFactory());
			out.writeBytes(identifiableKey.getKey());
		}
		
		@Override
		public IdentifiableKey deserialize(FieldInputStream in, Settings settings)
		{
			return new IdentifiableKey(in.readObject(settings.getUIDFactory()), in.readBytes());
		}
	};
	
	/**
	 * Identifier of the key
	 */
	private final UID uid;
	private final byte[] key;
	
	public IdentifiableKey(UID uid, byte[] key)
	{
		this.uid = uid;
		this.key = key;
	}
	
	public UID getUID()
	{
		return uid;
	}
	
	public byte[] getKey()
	{
		return key;
	}
}