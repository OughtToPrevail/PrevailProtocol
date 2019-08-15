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
package oughttoprevail.prevailprotocol.nonce;

import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.Storage;
import oughttoprevail.prevailprotocol.storage.fields.CounterField;

/**
 * A counter based implementation of {@link NonceGenerator}.
 */
public class ServerNonceGenerator extends NonceGenerator
{
	/**
	 * The nonce counter
	 */
	private final CounterField nonceCounter;
	
	/**
	 * Constructs a new {@link ServerNonceGenerator} with the specified storage to create the field with
	 * and specified settings.
	 *
	 * @param storage to create the field with
	 * @param settings to use
	 */
	public ServerNonceGenerator(Storage storage, Settings settings)
	{
		super(settings, settings.getNonceSize(), "nonceSize");
		nonceCounter = new CounterField(storage);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	byte[] getCounterBytes()
	{
		try
		{
			return nonceCounter.getBytes();
		} finally
		{
			nonceCounter.increment();
		}
	}
}