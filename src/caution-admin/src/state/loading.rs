// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::AppState;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AwsLoadMode {
    Open,
    Refresh,
}

impl AppState {
    pub fn begin_aws_load(&mut self, mode: AwsLoadMode) {
        self.aws_loading = Some(mode);
        self.aws_loading_frame = 0;
        self.current.status = None;
    }

    pub fn advance_aws_loading(&mut self) {
        if self.aws_loading.is_some() {
            self.aws_loading_frame = self.aws_loading_frame.wrapping_add(1);
        }
    }

    pub fn finish_aws_load(&mut self) {
        self.aws_loading = None;
        self.aws_loading_frame = 0;
    }
}
