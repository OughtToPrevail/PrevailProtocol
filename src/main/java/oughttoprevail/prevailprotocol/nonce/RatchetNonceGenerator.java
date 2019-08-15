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

import oughttoprevail.prevailprotocol.session.Session;
import oughttoprevail.prevailprotocol.settings.Settings;

/**
 * A {@link Session#getSendingRatchet()} based implementation of {@link NonceGenerator}.
 */
public abstract class RatchetNonceGenerator extends NonceGenerator
{
	/**
	 * Constructs a new {@link RatchetNonceGenerator} with the specified settings.
	 *
	 * @param settings to use
	 */
	protected RatchetNonceGenerator(Settings settings)
	{
		super(settings, settings.getIVSize(), "ivSize");
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	byte[] getCounterBytes()
	{
		return getSession().getSendingRatchet().getCounterBytes();
	}
	
	/**
	 * @return the current session
	 */
	protected abstract Session getSession();
}