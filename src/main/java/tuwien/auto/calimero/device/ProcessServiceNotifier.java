/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2011, 2017 B. Malinowsky

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
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.KNXTimeoutException;
import tuwien.auto.calimero.link.KNXLinkClosedException;
import tuwien.auto.calimero.process.ProcessCommunicator;
import tuwien.auto.calimero.process.ProcessCommunicatorImpl;
import tuwien.auto.calimero.process.ProcessEvent;
import tuwien.auto.calimero.process.ProcessListener;

final class ProcessServiceNotifier implements ServiceNotifier<ProcessCommunicationService>, ProcessListener
{
	private static final int GROUP_READ = 0x00;
	private static final int GROUP_RESPONSE = 0x40;
	private static final int GROUP_WRITE = 0x80;

	private final BaseKnxDevice device;
	private ProcessCommunicationService svc;
	private final ProcessCommunicator recv;
	private final ProcessCommunicationResponder res;

	// pre-condition: knxDevice != null, link != null
	ProcessServiceNotifier(final BaseKnxDevice device) throws KNXLinkClosedException
	{
		if (device == null)
			throw new NullPointerException("KNX device is required");
		this.device = device;
		recv = new ProcessCommunicatorImpl(device.getDeviceLink());
		recv.addProcessListener(this);
		res = new ProcessCommunicationResponder(device.getDeviceLink());
	}

	public void groupReadRequest(final ProcessEvent e)
	{
		device.dispatch(this, e);
	}

	public void groupReadResponse(final ProcessEvent e)
	{
		device.dispatch(this, e);
	}
	public void groupWrite(final ProcessEvent e)
	{
		device.dispatch(this, e);
	}

	public void detached(final DetachEvent e) {}

	public ServiceResult dispatch(final EventObject e)
	{
		if (svc == null)
			return null;
		final ProcessEvent pe =  (ProcessEvent) e;
		final int svcCode = pe.getServiceCode();
		if (svcCode == GROUP_READ)
			return svc.groupReadRequest(pe);
		else if (svcCode == GROUP_WRITE)
			svc.groupWrite(pe);
		else if (svcCode == GROUP_RESPONSE)
			svc.groupResponse(pe);
		else
			throw new KNXIllegalArgumentException("no KNX process service of type " + svcCode);
		return null;
	}

	public void response(final EventObject event, final ServiceResult sr)
	{
		final GroupAddress to = ((ProcessEvent) event).getDestination();
		if (sr.getResult() != null) {
			try {
				res.setPriority(sr.getPriority());
				res.write(to, sr.getResult(), sr.compact);
			}
			catch (KNXTimeoutException | KNXLinkClosedException e) {
				device.logger().error("responding to {}: {}", to, DataUnitBuilder.toHex(sr.getResult(), " "), e);
			}
		}
		else
			sr.run();
	}

	public void setServiceInterface(final ProcessCommunicationService svcIf)
	{
		svc = svcIf;
	}
}