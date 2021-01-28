/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2011, 2021 B. Malinowsky

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

import java.util.EventObject;

import tuwien.auto.calimero.DataUnitBuilder;
import tuwien.auto.calimero.DetachEvent;
import tuwien.auto.calimero.GroupAddress;
import tuwien.auto.calimero.KNXTimeoutException;
import tuwien.auto.calimero.link.KNXLinkClosedException;
import tuwien.auto.calimero.process.ProcessCommunicator;
import tuwien.auto.calimero.process.ProcessCommunicatorImpl;
import tuwien.auto.calimero.process.ProcessEvent;
import tuwien.auto.calimero.process.ProcessListener;

final class ProcessServiceNotifier implements ProcessListener, AutoCloseable
{
	static final int GROUP_READ = 0x00;
	static final int GROUP_RESPONSE = 0x40;
	static final int GROUP_WRITE = 0x80;

	private final BaseKnxDevice device;
	private final ProcessCommunicationService svc;
	private final ProcessCommunicator recv;
	private final ProcessCommunicationResponder res;


	// pre-condition: device != null, device.link != null
	ProcessServiceNotifier(final BaseKnxDevice device, final ProcessCommunicationService service)
		throws KNXLinkClosedException
	{
		if (device.getDeviceLink() == null)
			throw new NullPointerException("KNX device network link is required");
		this.device = device;
		svc = service;

		recv = new ProcessCommunicatorImpl(device.getDeviceLink(), device.sal);
		res = new ProcessCommunicationResponder(device.getDeviceLink(), device.sal);
		recv.addProcessListener(this);
	}

	@Override
	public void groupReadRequest(final ProcessEvent e)
	{
		device.dispatch(e, () -> svc.groupReadRequest(e), this::respond);
	}

	@Override
	public void groupReadResponse(final ProcessEvent e)
	{
		device.dispatch(e, () -> { svc.groupResponse(e); return null; }, this::respond);
	}

	@Override
	public void groupWrite(final ProcessEvent e)
	{
		device.dispatch(e, () -> { svc.groupWrite(e); return null; }, this::respond);
	}

	@Override
	public void detached(final DetachEvent e) {}

	void respond(final EventObject event, final ServiceResult<byte[]> sr)
	{
		if (sr.result() != null) {
			final GroupAddress to = ((ProcessEvent) event).getDestination();
			try {
				res.setPriority(sr.getPriority());
				res.write(to, sr.result(), sr.compact);
			}
			catch (KNXTimeoutException | KNXLinkClosedException e) {
				device.logger().error("responding to {}: {}", to, DataUnitBuilder.toHex(sr.result(), " "), e);
			}
		}
		else
			sr.run();
	}

	@Override
	public void close()
	{
		recv.close();
		res.close();
	}
}