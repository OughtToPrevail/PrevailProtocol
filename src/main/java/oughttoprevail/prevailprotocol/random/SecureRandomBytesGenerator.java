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
package oughttoprevail.prevailprotocol.random;

import java.security.SecureRandom;

/**
 * A {@link SecureRandom} based implementation of {@link RandomBytesGenerator}
 */
public class SecureRandomBytesGenerator implements RandomBytesGenerator
{
	/**
	 * Random {@code byte[]} generator
	 */
	private final SecureRandom secureRandom = new SecureRandom();
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] nextBytes(int length)
	{
		byte[] bytes = new byte[length];
		secureRandom.nextBytes(bytes);
		return bytes;
	}
}