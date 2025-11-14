/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package test;

import static android.uprobestats.flags.Flags.FLAG_ENABLE_UPROBESTATS;
import static android.uprobestats.flags.Flags.FLAG_EXECUTABLE_METHOD_FILE_OFFSETS;
import static android.uprobestats.mainline.flags.Flags.FLAG_ENABLE_BITMAP_INSTRUMENTATION;
import static android.uprobestats.mainline.flags.Flags.FLAG_UPROBESTATS_MONITOR_DISRUPTIVE_APP_ACTIVITIES;

import static com.google.common.truth.Truth.assertThat;

import static org.junit.Assume.assumeTrue;

import static test.SmokeTestSetup.configureStatsDAndStartUprobeStats;
import static test.SmokeTestSetup.initializeStatsD;
import static test.SmokeTestSetup.initializeUprobeStats;

import android.cts.statsdatom.lib.AtomTestUtils;
import android.cts.statsdatom.lib.DeviceUtils;
import android.cts.statsdatom.lib.ReportUtils;
import android.platform.test.annotations.RequiresFlagsEnabled;
import android.platform.test.flag.junit.CheckFlagsRule;
import android.platform.test.flag.junit.host.HostFlagsValueProvider;

import com.android.compatibility.common.util.CpuFeatures;
import com.android.os.StatsLog;
import com.android.os.uprobestats.BindServiceLockedWithBalFlagsReported;
import com.android.os.uprobestats.SetComponentEnabledSettingReported;
import com.android.os.uprobestats.UprobestatsExtensionAtoms;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
import com.android.tradefed.util.RunUtil;

import com.google.protobuf.ExtensionRegistry;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.List;

@RunWith(DeviceJUnit4ClassRunner.class)
public class SmokeTestRustOnly extends BaseHostJUnit4Test {
    private static final String TEST_MALWARE_SIGNAL_CONFIG = "disruptive_app.textproto";
    private static final String BITMAP_ALLOCATION_CONFIG = "bitmap.textproto";
    private static final String BITMAP_TESTAPP_PACKAGE_NAME = "com.android.uprobestats.bitmap";
    private ExtensionRegistry mRegistry;

    @Rule
    public final CheckFlagsRule mCheckFlagsRule =
            HostFlagsValueProvider.createCheckFlagsRule(this::getDevice);

    @Before
    public void setUp() throws Exception {
        mRegistry = initializeStatsD(getDevice());
        initializeUprobeStats(getDevice());
    }

    @Test
    @RequiresFlagsEnabled({
        FLAG_ENABLE_UPROBESTATS,
        FLAG_EXECUTABLE_METHOD_FILE_OFFSETS,
        FLAG_UPROBESTATS_MONITOR_DISRUPTIVE_APP_ACTIVITIES,
    })
    public void disruptiveAppActivity() throws Exception {
        assumeTrue(CpuFeatures.isArm64(getDevice()));

        configureStatsDAndStartUprobeStats(
                getClass(),
                getDevice(),
                TEST_MALWARE_SIGNAL_CONFIG,
                UprobestatsExtensionAtoms.SET_COMPONENT_ENABLED_SETTING_REPORTED_FIELD_NUMBER,
                UprobestatsExtensionAtoms.BIND_SERVICE_LOCKED_WITH_BAL_FLAGS_REPORTED_FIELD_NUMBER);

        // enable and disable a component (need one that will definitely exist, but not in
        // android/com.android namespace)
        getDevice()
                .executeShellCommand(
                        "pm disable" + " com.android.uprobestats.disruptive/.TestActivity");
        getDevice()
                .executeShellCommand(
                        "pm enable" + " com.android.uprobestats.disruptive/.TestActivity");

        getDevice()
                .executeShellCommand(
                        "am start -n" + " com.android.uprobestats.disruptive/.TestActivity");

        // Allow UprobeStats/StatsD time to collect metric
        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);

        // See if the atom made it
        List<StatsLog.EventMetricData> data =
                ReportUtils.getEventMetricDataList(getDevice(), mRegistry);
        assertThat(data.size()).isEqualTo(2);

        SetComponentEnabledSettingReported reported =
                data.get(0)
                        .getAtom()
                        .getExtension(UprobestatsExtensionAtoms.setComponentEnabledSettingReported);
        assertThat(reported.getNewState())
                .isEqualTo(2); // PackageManager.COMPONENT_ENABLED_STATE_DISABLED;
        assertThat(reported.getPackageName()).isEqualTo("com.android.uprobestats.disruptive");
        assertThat(reported.getClassName())
                .isEqualTo("com.android.uprobestats.disruptive.TestActivity");
        assertThat(reported.getCallingPackageName()).isEqualTo("shell");

        BindServiceLockedWithBalFlagsReported balReported =
                data.get(1)
                        .getAtom()
                        .getExtension(
                                UprobestatsExtensionAtoms.bindServiceLockedWithBalFlagsReported);
        assertThat(balReported.getCallingPackageName())
                .isEqualTo("com.android.uprobestats.disruptive");
        assertThat(balReported.getFlags())
                .isEqualTo(1048576); // Context.BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS
        assertThat(balReported.getIntentPackageName()).isEqualTo("");
    }

    @Test
    @RequiresFlagsEnabled({
        FLAG_ENABLE_UPROBESTATS,
        FLAG_EXECUTABLE_METHOD_FILE_OFFSETS,
        com.android.art.flags.Flags.FLAG_EXECUTABLE_METHOD_FILE_OFFSETS_V2,
        FLAG_ENABLE_BITMAP_INSTRUMENTATION,
    })
    public void bitmapAllocation() throws Exception {
        assumeTrue(CpuFeatures.isArm64(getDevice()));
        final int uid = DeviceUtils.getAppUid(getDevice(), BITMAP_TESTAPP_PACKAGE_NAME);

        configureStatsDAndStartUprobeStats(
                getClass(),
                getDevice(),
                BITMAP_ALLOCATION_CONFIG,
                UprobestatsExtensionAtoms.ANDROID_GRAPHICS_BITMAP_ALLOCATED_FIELD_NUMBER);

        try (AutoCloseable a =
                DeviceUtils.withActivity(
                        getDevice(),
                        BITMAP_TESTAPP_PACKAGE_NAME,
                        "BitmapTestActivity",
                        "action",
                        "action.lmk")) {

            // Allow UprobeStats/StatsD time to collect metric
            RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);

            // See if the atom made it
            List<StatsLog.EventMetricData> data =
                    ReportUtils.getEventMetricDataList(getDevice(), mRegistry);
            assertThat(data.size()).isGreaterThan(0);
            boolean anyMatch =
                    data.stream()
                            .map(StatsLog.EventMetricData::getAtom)
                            .filter(
                                    atom ->
                                            atom.hasExtension(
                                                    UprobestatsExtensionAtoms
                                                            .androidGraphicsBitmapAllocated))
                            .map(
                                    atom ->
                                            atom.getExtension(
                                                    UprobestatsExtensionAtoms
                                                            .androidGraphicsBitmapAllocated))
                            .anyMatch(
                                    reported ->
                                            reported.getWidth() == 100
                                                    && reported.getHeight() == 100
                                                    && reported.getUid() == uid);
            assertThat(anyMatch).isTrue();
        }
    }
}
