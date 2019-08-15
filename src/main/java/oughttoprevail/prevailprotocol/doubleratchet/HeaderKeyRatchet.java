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
package oughttoprevail.prevailprotocol.doubleratchet;

import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.Storage;
import oughttoprevail.prevailprotocol.storage.fields.Field;
import oughttoprevail.prevailprotocol.storage.fields.JavaSerDes;

/**
 * A {@link HeaderKeyRatchet} provides secrecy for message headers.
 * Quoted from Double-Ratchet documentation:
 * "Message headers contain ratchet public keys and (PN, N) values. In some cases it may be desirable to encrypt the headers so that an eavesdropper
 * can't tell which messages belong to which sessions, or the ordering of messages within a session."
 *
 * @see <a href="https://signal.org/docs/specifications/doubleratchet/">Double-Ratchet</a>
 */
public class HeaderKeyRatchet
{
	/**
	 * Storage to store header keys in
	 */
	private final Storage storage;
	/**
	 * Current header chain key
	 */
	private final Field<byte[]> headerChainKey;
	/**
	 * Current authentication header key, used for creating mac's of the encrypted ciphertext from {@link #headerChainKey} if {@link Settings#isUseUpdateAAD()}
	 * is {@code false}
	 */
	private final Field<byte[]> authHeaderKey;
	/**
	 * The next header chain key, to be set as the current header chain key once a new header chain key is generated
	 */
	private final Field<byte[]> nextHeaderChainKey;
	/**
	 * Next authentication header key, used for creating mac's of the encrypted ciphertext from {@link #nextHeaderChainKey} if {@link Settings#isUseUpdateAAD()}
	 * is {@code false}
	 */
	private final Field<byte[]> nextAuthHeaderKey;
	
	/**
	 * Constructs a new {@link HeaderKeyRatchet}.
	 *
	 * @param storage to store header keys in
	 */
	public HeaderKeyRatchet(Storage storage)
	{
		this.storage = storage;
		headerChainKey = storage.getField(JavaSerDes.BYTE_ARRAY_SER_DES);
		authHeaderKey = storage.getField(JavaSerDes.BYTE_ARRAY_SER_DES);
		nextHeaderChainKey = storage.getField(JavaSerDes.BYTE_ARRAY_SER_DES);
		nextAuthHeaderKey = storage.getField(JavaSerDes.BYTE_ARRAY_SER_DES);
	}
	
	/**
	 * Initializes the keys to the specified values.
	 *
	 * @param headerChainKey to be the {@link #headerChainKey} value
	 * @param authHeaderKey to be the {@link #authHeaderKey} value
	 * @param nextHeaderChainKey to be the {@link #nextHeaderChainKey} value
	 * @param nextAuthHeaderKey to be the {@link #nextAuthHeaderKey} value
	 */
	public void init(byte[] headerChainKey, byte[] authHeaderKey, byte[] nextHeaderChainKey, byte[] nextAuthHeaderKey)
	{
		this.headerChainKey.set(headerChainKey);
		this.authHeaderKey.set(authHeaderKey);
		this.nextHeaderChainKey.set(nextHeaderChainKey);
		this.nextAuthHeaderKey.set(nextAuthHeaderKey);
	}
	
	/**
	 * Performs a header key ratchet step with the specified values.
	 *
	 * @param nextHeaderChainKey to be the next header chain key
	 * @param nextAuthHeaderKey to be the next authentication header key (possibly {@code null} if authentication header keys aren't required)
	 */
	void step(byte[] nextHeaderChainKey, byte[] nextAuthHeaderKey)
	{
		this.headerChainKey.set(this.nextHeaderChainKey.get());
		this.authHeaderKey.set(this.nextAuthHeaderKey.get());
		this.nextHeaderChainKey.set(nextHeaderChainKey);
		this.nextAuthHeaderKey.set(nextAuthHeaderKey);
		storage.flush();
	}
	
	public byte[] getHeaderChainKey()
	{
		return headerChainKey.get();
	}
	
	public byte[] getAuthHeaderKey()
	{
		return authHeaderKey.get();
	}
	
	public byte[] getNextHeaderChainKey()
	{
		return nextHeaderChainKey.get();
	}
	
	public byte[] getNextAuthHeaderKey()
	{
		return nextAuthHeaderKey.get();
	}
}