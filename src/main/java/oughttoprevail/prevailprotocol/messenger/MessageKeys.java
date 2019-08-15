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
package oughttoprevail.prevailprotocol.messenger;

import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.util.IvSpec;
import oughttoprevail.prevailprotocol.util.KeySpec;
import oughttoprevail.prevailprotocol.util.Util;

/**
 * A {@link MessageKeys} is a container for the result of a {@link oughttoprevail.prevailprotocol.doubleratchet.SymmetricKeyRatchet} key derivation.
 */
public class MessageKeys
{
	/**
	 * Key to encrypt/decrypt message with
	 */
	private final KeySpec messageKey;
	/**
	 * Initialization vector for the message
	 */
	private final IvSpec iv;
	/**
	 * Optional mac key for message verification
	 */
	private final KeySpec macKey;
	
	/**
	 * Constructs a new {@link MessageKeys}.
	 *
	 * @param settings to use
	 */
	public MessageKeys(Settings settings, byte[] messageKey, byte[] iv, byte[] macKey)
	{
		this.messageKey = Util.newSymmetricKey(messageKey, settings);
		this.iv = Util.newIV(iv, settings);
		this.macKey = macKey == null ? null : Util.newMacKey(macKey, settings);
	}
	
	public KeySpec getMessageKey()
	{
		return messageKey;
	}
	
	public IvSpec getIV()
	{
		return iv;
	}
	
	public KeySpec getMacKey()
	{
		return macKey;
	}
}