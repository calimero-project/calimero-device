/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2012, 2014 B. Malinowsky

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

package tuwien.auto.calimero.device;

import java.util.LinkedList;
import java.util.List;

class TaskRunner extends Thread
{
	private final List<Runnable> tasks = new LinkedList<>();

	/**
	 * Creates a new task runner.
	 * <p>
	 */
	public TaskRunner()
	{
		setDaemon(true);
		setName("KNX device task runner");
	}

	/* (non-Javadoc)
	 * @see java.lang.Thread#run()
	 */
	public void run()
	{
		try {
			while (true) {
				Runnable r = null;
				if (tasks.isEmpty()) {
					synchronized (this) {
						wait();
						if (!tasks.isEmpty())
							r = tasks.remove(0);
					}
				}
				if (r == null) {
					synchronized (this) {
						r = tasks.remove(0);
					}
				}
				try {
					r.run();
				}
				catch (final RuntimeException e) {
					e.printStackTrace();
				}
			}
		}
		catch (final InterruptedException e) {
			e.printStackTrace();
		}
	}

	public synchronized final void runTask(final Runnable task)
	{
		tasks.add(task);
		notify();
	}
};
