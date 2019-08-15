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
package oughttoprevail.prevailprotocol.kdf;

import javax.crypto.Mac;

import oughttoprevail.prevailprotocol.settings.Settings;

/**
 * A {@link HKDF} creation factory implementation of {@link KDFFactory}.
 */
public class HKDFFactory implements KDFFactory
{
	/**
	 * {@inheritDoc}
	 */
	@Override
	public KDF newKDF(Mac mac, Settings settings)
	{
		return new HKDF(mac, settings);
	}
}