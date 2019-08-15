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

import java.util.concurrent.ScheduledFuture;

import oughttoprevail.prevailprotocol.messenger.MessageKeys;
import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.fields.FieldInputStream;
import oughttoprevail.prevailprotocol.storage.fields.FieldOutputStream;
import oughttoprevail.prevailprotocol.storage.fields.SerDes;

/**
 * A {@link SkippedKey} necessary information about a key to later use it (when retrieved).
 */
public class SkippedKey
{
	public static final SerDes<SkippedKey> SER_DES = new SerDes<SkippedKey>()
	{
		@Override
		public void serialize(SkippedKey storedMessageKeys, FieldOutputStream out, Settings settings)
		{
			out.writeInt(storedMessageKeys.getCounter());
			out.writeBytes(storedMessageKeys.getKey());
			out.writeBoolean(storedMessageKeys.getAuthKey() != null);
			if(storedMessageKeys.getAuthKey() != null)
			{
				out.writeBytes(storedMessageKeys.getAuthKey());
			}
			out.writeLong(storedMessageKeys.getExpirationTime());
			MessageKeys messageKeys = storedMessageKeys.messageKeys;
			out.writeBytes(messageKeys.getMessageKey().getKey());
			out.writeBytes(messageKeys.getIV().getIV());
			out.writeBoolean(messageKeys.getMacKey() != null);
			if(messageKeys.getMacKey() != null)
			{
				out.writeBytes(messageKeys.getMacKey().getKey());
			}
		}
		
		@Override
		public SkippedKey deserialize(FieldInputStream in, Settings settings)
		{
			return new SkippedKey(in.readInt(),
					in.readBytes(),
					in.readBoolean() ? in.readBytes() : null,
					in.readLong(),
					new MessageKeys(settings, in.readBytes(), in.readBytes(), in.readBoolean() ? in.readBytes() : null));
		}
	};
	
	/**
	 * Counter of the {@link oughttoprevail.prevailprotocol.doubleratchet.SymmetricKeyRatchet} before skipping
	 */
	private final int counter;
	/**
	 * Key identifier
	 */
	private final byte[] key;
	/**
	 * Optional authentication key
	 */
	private final byte[] authKey;
	/**
	 * When to this {@link SkippedKey} expires, when it expires it should be removed
	 */
	private final long expirationTime;
	/**
	 * Deletion future
	 */
	private ScheduledFuture<?> future;
	/**
	 * Message keys which were skipped
	 */
	private final MessageKeys messageKeys;
	
	public SkippedKey(int counter, byte[] key, byte[] authKey, long expirationTime, MessageKeys messageKeys)
	{
		this.counter = counter;
		this.key = key;
		this.authKey = authKey;
		this.expirationTime = expirationTime;
		this.messageKeys = messageKeys;
	}
	
	public int getCounter()
	{
		return counter;
	}
	
	public byte[] getKey()
	{
		return key;
	}
	
	public byte[] getAuthKey()
	{
		return authKey;
	}
	
	public long getExpirationTime()
	{
		return expirationTime;
	}
	
	/**
	 * Sets the deletion future.
	 *
	 * @param future deletion future
	 */
	public void setFuture(ScheduledFuture<?> future)
	{
		this.future = future;
	}
	
	/**
	 * Cancels deletion of the {@link SkippedKey} and returns it's {@link MessageKeys}.
	 *
	 * @return the {@link MessageKeys}
	 */
	public MessageKeys cancelThenGetMessageKeys()
	{
		if(future != null)
		{
			future.cancel(false);
		}
		return messageKeys;
	}
}