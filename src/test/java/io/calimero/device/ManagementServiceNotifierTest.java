/*
    Calimero 3 - A library for KNX network access
    Copyright (c) 2019, 2025 B. Malinowsky

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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.util.function.Consumer;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.calimero.DataUnitBuilder;
import io.calimero.DeviceDescriptor;
import io.calimero.FrameEvent;
import io.calimero.GroupAddress;
import io.calimero.IndividualAddress;
import io.calimero.KNXAddress;
import io.calimero.KNXException;
import io.calimero.Priority;
import io.calimero.ReturnCode;
import io.calimero.cemi.CEMI;
import io.calimero.cemi.CEMILData;
import io.calimero.cemi.CEMILDataEx;
import io.calimero.datapoint.Datapoint;
import io.calimero.datapoint.StateDP;
import io.calimero.device.ios.InterfaceObject;
import io.calimero.dptxlator.DPTXlator;
import io.calimero.dptxlator.DPTXlatorBoolean;
import io.calimero.dptxlator.PropertyTypes;
import io.calimero.link.AbstractLink;
import io.calimero.link.KNXLinkClosedException;
import io.calimero.link.KNXNetworkLink;
import io.calimero.link.medium.TPSettings;
import io.calimero.mgmt.Description;

class ManagementServiceNotifierTest {

	private ManagementServiceNotifier notifier;

	// link stub, does nothing
	private final KNXNetworkLink linkStub = new AbstractLink<>("test link",
			new TPSettings(new IndividualAddress(0, 0x02, 0xff))) {
		@Override
		protected void onSend(final CEMILData msg, final boolean waitForCon) {}

		@Override
		protected void onSend(final KNXAddress dst, final byte[] msg, final boolean waitForCon) {}
	};

	// re-use default logic of management services
	private final KnxDeviceServiceLogic mgmtServices = new KnxDeviceServiceLogic() {
		@Override
		public void updateDatapointValue(final Datapoint ofDp, final DPTXlator update) {
//			fail("not under test");
		}

		@Override
		public DPTXlator requestDatapointValue(final Datapoint ofDp) throws KNXException {
//			fail("not under test");
			final var t = new DPTXlatorBoolean(DPTXlatorBoolean.DPT_SWITCH);
			t.setData(new byte[] { 1 });
			return t;
		}
	};

	private Consumer<byte[]> test;
	private boolean testFinished;

	private int groupObjectTableIndex;

	@BeforeEach
	void init() throws KNXLinkClosedException {
		final BaseKnxDevice device = new BaseKnxDevice("test", DeviceDescriptor.DD0.TYPE_5705,
				linkStub, null, mgmtServices);
		mgmtServices.setDevice(device);
		final var ios = device.getInterfaceObjectServer();
		for (final var io : ios.getInterfaceObjects()) {
			if (io.getType() == InterfaceObject.GROUP_OBJECT_TABLE_OBJECT) {
				groupObjectTableIndex = io.getIndex();
				break;
			}
		}

		ios.setDescription(
				new Description(groupObjectTableIndex, 0, 66, 0, PropertyTypes.PDT_FUNCTION, true, 1, 1, 3, 3), true);

		notifier = new ManagementServiceNotifier(device, mgmtServices) {
			@Override
			void send(final io.calimero.mgmt.Destination respondTo, final byte[] apdu, final Priority p,
				final String service) {
				test.accept(apdu);
				testFinished = true;
			}
		};
		device.mgmtNotifier = notifier;
	}

	@Test
	void memoryExtendedWriteIllegalLength() {
		final byte[] asdu = { (byte) 254, 1, 2, 3, 0, 0, 0, 0 };

		test = apdu -> assertEquals(ReturnCode.ExceedsMaxApduLength, ReturnCode.of(apdu[2] & 0xff));
		assertResponse(ManagementServiceNotifier.MemoryExtendedWrite, asdu);
	}

	@Test
	void memoryExtendedReadIllegalLength() {
		final byte[] asdu = { (byte) 254, 1, 2, 3 };

		test = apdu -> assertEquals(ReturnCode.ExceedsMaxApduLength, ReturnCode.of(apdu[2] & 0xff));
		assertResponse(ManagementServiceNotifier.MemoryExtendedRead, asdu);
	}

	@Test
	void memoryExtendedWriteDataOverflow() {
		final byte[] asdu = { (byte) 2, 0x1, 0x01, (byte) 0xff, 1, 2 };
		test = apdu -> assertEquals(ReturnCode.MemoryError, ReturnCode.of(apdu[2] & 0xff));
		assertResponse(ManagementServiceNotifier.MemoryExtendedWrite, asdu);
	}

	@Test
	void memoryExtendedWriteNonExistingAddress() {
		final byte[] asdu = { (byte) 1, 0x10, 0x00, 0x00, 1 };
		test = apdu -> assertEquals(ReturnCode.AddressVoid, ReturnCode.of(apdu[2] & 0xff));
		assertResponse(ManagementServiceNotifier.MemoryExtendedWrite, asdu);
	}

	@Test
	void memoryExtendedReadNonExistingAddress() {
		final byte[] asdu = { (byte) 1, 0x10, 0x00, 0x00 };
		test = apdu -> assertEquals(ReturnCode.AddressVoid, ReturnCode.of(apdu[2] & 0xff));
		assertResponse(ManagementServiceNotifier.MemoryExtendedRead, asdu);
	}

	@Test
	void goDiagnosticsSendGroupValueWrite() {
		final var group = new GroupAddress(1, 1, 5);
		mgmtServices.getDatapointModel().add(new StateDP(group, "test datapoint", 0, "1.001"));

		sendGroupObjectDiagnostics(group, 1, ReturnCode.Success);
	}

	@Test
	void goDiagnosticsSendNonExistingGroupValueWrite() {
		final var group = new GroupAddress(1, 1, 6);

		sendGroupObjectDiagnostics(group, 1, ReturnCode.DataVoid);
	}

	@Test
	void goDiagnosticsSendGroupValueRead() {
		final var group = new GroupAddress(1, 1, 5);
		mgmtServices.getDatapointModel().add(new StateDP(group, "test datapoint", 0, "1.001"));

		sendGroupObjectDiagnostics(group, 3, ReturnCode.Success);
	}

	private void sendGroupObjectDiagnostics(final GroupAddress group, final int service, final ReturnCode returnCode) {
		final byte objectIndex = (byte) groupObjectTableIndex;
		final byte pidGODiagnostics = (byte) 66;
		final var buffer = ByteBuffer.allocate(10).put(objectIndex).put(pidGODiagnostics).put((byte) 0)
				.put((byte) service).put((byte) 0).put(group.toByteArray());
		test = apdu -> {
			assertEquals(objectIndex, apdu[2] & 0xff);
			assertEquals(pidGODiagnostics, apdu[3] & 0xff);
			assertEquals(returnCode, ReturnCode.of(apdu[4] & 0xff));
			assertEquals(service, apdu[5] & 0xff);
		};
		assertResponse(ManagementServiceNotifier.FunctionPropertyCommand, buffer.array());
	}

	private void assertResponse(final int svc, final byte[] asdu) {
		final IndividualAddress src = new IndividualAddress(1, 1, 1);
		final KNXAddress dst = new IndividualAddress(2, 2, 2);
		final byte[] tpdu = DataUnitBuilder.createAPDU(svc, asdu);
		final CEMI frame = new CEMILDataEx(CEMILData.MC_LDATA_IND, src, dst, tpdu, Priority.LOW);
		final FrameEvent e = new FrameEvent(this, frame);
		final ServiceResult<Void> sr = ServiceResult.empty();

		notifier.respond(e, sr);
		assertTrue(testFinished, "test for asserting response did no finish");
	}
}
