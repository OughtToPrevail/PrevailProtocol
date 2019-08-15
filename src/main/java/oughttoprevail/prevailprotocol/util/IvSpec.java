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
package oughttoprevail.prevailprotocol.util;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.spec.AlgorithmParameterSpec;

/**
 * A {@link IvSpec} should be equal to other implementations except adds a {@link #getIV()} method which returned the untouched iv unlike
 * {@link IvParameterSpec#getIV()} and {@link GCMParameterSpec#getIV()} which return clones of the iv.
 */
public interface IvSpec extends AlgorithmParameterSpec
{
	/**
	 * @return the iv wrapped in this spec
	 */
	byte[] getIV();
}