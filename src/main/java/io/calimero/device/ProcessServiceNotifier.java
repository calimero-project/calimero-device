/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2011, 2024 B. Malinowsky

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

import static java.lang.System.Logger.Level.ERROR;

import java.util.EventObject;
import java.util.HexFormat;

import io.calimero.DataUnitBuilder;
import io.calimero.DetachEvent;
import io.calimero.FrameEvent;
import io.calimero.GroupAddress;
import io.calimero.KNXTimeoutException;
import io.calimero.cemi.CEMILData;
import io.calimero.cemi.CEMILDataEx;
import io.calimero.link.KNXLinkClosedException;
import io.calimero.link.NetworkLinkListener;
import io.calimero.process.LteProcessEvent;
import io.calimero.process.ProcessCommunicator;
import io.calimero.process.ProcessCommunicatorImpl;
import io.calimero.process.ProcessEvent;
import io.calimero.process.ProcessListener;

final class ProcessServiceNotifier implements ProcessListener, AutoCloseable
{
	static final int GROUP_READ = 0x00;
	static final int GROUP_RESPONSE = 0x40;
	static final int GROUP_WRITE = 0x80;

	private static final int GroupPropRead = 0b1111101000;
	private static final int GroupPropResponse = 0b1111101001;
	static final int GroupPropWrite = 0b1111101010;
	static final int GroupPropInfo = 0b1111101011;

	private final BaseKnxDevice device;
	private final ProcessCommunicationService svc;
	private final ProcessCommunicator recv;
	private final ProcessCommunicationResponder res;

	private final class LteListener implements NetworkLinkListener {
		@Override
		public void indication(final FrameEvent e) {
			final CEMILData ldata = (CEMILData) e.getFrame();
			if (!(ldata instanceof CEMILDataEx))
				return;

			final var apdu = ldata.getPayload();
			// can't be a process communication indication if too short
			if (apdu.length < 2)
				return;

			try {
				final byte[] data = ldata.toByteArray();
				final int ctrl2 = data[3 + data[1]] & 0xff;
				if ((ctrl2 & 0x04) == 0)
					return;

				final int svc = DataUnitBuilder.getAPDUService(apdu);
				if ((svc & 0b1111111100) == 0b1111101000) {
					// group property service
					final byte[] tpdu = ldata.getPayload();
					fireGroupReadWrite(ldata, ctrl2 & 0x0f, tpdu, svc);
				}
			}
			catch (final RuntimeException rte) {
				device.logger().log(ERROR, "on group property indication from {0}", ldata.getSource(), rte);
			}
		}

		private void fireGroupReadWrite(final CEMILData f, final int eff, final byte[] tpdu, final int svc) {
			final ProcessEvent e = new LteProcessEvent(ProcessServiceNotifier.this.recv, f.getSource(), eff,
					(GroupAddress) f.getDestination(), tpdu);
			if (svc == GroupPropRead)
				groupReadRequest(e);
			else if (svc == GroupPropInfo)
				groupLteInfo(e);
			else if (svc == GroupPropWrite)
				groupWrite(e);
		}
	}

	private final boolean lte = true;

	// pre-condition: device != null, device.link != null
	ProcessServiceNotifier(final BaseKnxDevice device, final ProcessCommunicationService service)
		throws KNXLinkClosedException
	{
		if (device.getDeviceLink() == null)
			throw new NullPointerException("KNX device network link is required");
		this.device = device;
		svc = service;

		recv = new ProcessCommunicatorImpl(device.getDeviceLink(), device.sal, false);
		res = new ProcessCommunicationResponder(device.getDeviceLink(), device.sal);
		recv.addProcessListener(this);

		if (lte)
			device.getDeviceLink().addLinkListener(new LteListener());
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

	public void groupLteInfo(final ProcessEvent e)
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
				device.logger().log(ERROR, "responding to {0}: {1}", to, HexFormat.ofDelimiter(" ").formatHex(sr.result()), e);
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