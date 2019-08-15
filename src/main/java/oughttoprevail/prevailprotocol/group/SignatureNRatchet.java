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
package oughttoprevail.prevailprotocol.group;

import oughttoprevail.prevailprotocol.doubleratchet.SymmetricKeyRatchet;
import oughttoprevail.prevailprotocol.storage.Storage;
import oughttoprevail.prevailprotocol.storage.fields.Field;
import oughttoprevail.prevailprotocol.storage.fields.JavaSerDes;

/**
 * A storage for signature public key for verification and a {@link SymmetricKeyRatchet} which will act as a receiving ratchet.
 */
class SignatureNRatchet
{
	/**
	 * Signature key for message verification
	 */
	private final Field<byte[]> signatureKey;
	/**
	 * Receiving ratchet for {@link oughttoprevail.prevailprotocol.messenger.MessageKeys} derivation
	 */
	private final SymmetricKeyRatchet receivingRatchet;
	
	/**
	 * Constructs a new {@link SignatureNRatchet}.
	 *
	 * @param receivingRatchet to be the receiving ratchet
	 * @param signatureKey initial value of the signature key or {@code null} if the value shouldn't be updated
	 * @param storage to store signature key in
	 */
	SignatureNRatchet(SymmetricKeyRatchet receivingRatchet, byte[] signatureKey, Storage storage)
	{
		this.signatureKey = storage.getField(JavaSerDes.BYTE_ARRAY_SER_DES);
		if(signatureKey != null)
		{
			this.signatureKey.set(signatureKey);
		}
		this.receivingRatchet = receivingRatchet;
	}
	
	byte[] getSignatureKey()
	{
		return signatureKey.get();
	}
	
	SymmetricKeyRatchet getReceivingRatchet()
	{
		return receivingRatchet;
	}
}