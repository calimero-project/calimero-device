/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2021, 2021 B. Malinowsky

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    Linking this library statically or dynamically with other modules is
    making a combined work based on this library. Thus, the terms and
    conditions of the GNU General Public License cover the whole
    combination.

    As a special exception, the copyright holders of this library give you
    permission to link this library with independent modules to produce an
    executable, regardless of the license terms of these independent
    modules, and to copy and distribute the resulting executable under terms
    of your choice, provided that you also meet, for each linked independent
    module, the terms and conditions of the license of that module. An
    independent module is a module which is not derived from or based on
    this library. If you modify this library, you may extend this exception
    to your version of the library, but you are not obligated to do so. If
    you do not wish to do so, delete this exception statement from your
    version.
*/

package io.calimero.device;

import java.util.Arrays;
import java.util.concurrent.locks.ReentrantLock;

final class ThreadSafeByteArray implements KnxDevice.Memory {
	private final byte[] array;
	private final ReentrantLock lock = new ReentrantLock();

	ThreadSafeByteArray(final int size) { array = new byte[size]; }

	@Override
	public int size() { return array.length; }

	@Override
	public int get(final int offset) {
		lock.lock();
		try {
			return array[offset] & 0xff;
		}
		finally {
			lock.unlock();
		}
	}

	@Override
	public byte[] get(final int offset, final int bytes) {
		lock.lock();
		try {
			return Arrays.copyOfRange(array, offset, offset + bytes);
		}
		finally {
			lock.unlock();
		}
	}

	@Override
	public void set(final int offset, final int bite) {
		lock.lock();
		try {
			array[offset] = (byte) bite;
		}
		finally {
			lock.unlock();
		}
	}

	@Override
	public void set(final int offset, final byte... bites) {
		lock.lock();
		try {
			System.arraycopy(bites, 0, array, offset, bites.length);
		}
		finally {
			lock.unlock();
		}
	}
}
