# 功能規格 (Feature Specification): [FEATURE NAME]

**Feature Branch**: `[###-feature-name]`

**Created**: [DATE]

**Status**: Draft

**Input**: User description: "$ARGUMENTS"

**語言政策**: 產生的 spec.md MUST 使用繁體中文 (zh-TW)；程式碼、檔案路徑、指令、API 名稱與必要英文專有名詞可保留英文。

## 使用者情境與測試 (User Scenarios & Testing) *(mandatory)*

<!--
  IMPORTANT: User stories MUST be written in zh-TW and PRIORITIZED as user journeys ordered by importance.
  Each user story/journey must include BDD Given/When/Then acceptance scenarios and be INDEPENDENTLY TESTABLE - meaning if you implement just ONE of them,
  you should still have a viable MVP (Minimum Viable Product) that delivers value.

  Assign priorities (P1, P2, P3, etc.) to each story, where P1 is the most critical.
  Think of each story as a standalone slice of functionality that can be:
  - Developed independently
  - Tested independently
  - Deployed independently
  - Demonstrated to users independently
-->

### 使用者故事 1 - [Brief Title] (Priority: P1)

[Describe this user journey in plain language]

**優先順序理由**: [Explain the value and why it has this priority level]

**獨立測試**: [Describe how this can be tested independently - e.g., "Can be fully tested by [specific action] and delivers [specific value]"]

**BDD 驗收情境**:

1. **Given** [initial state], **When** [action], **Then** [expected outcome]
2. **Given** [initial state], **When** [action], **Then** [expected outcome]

---

### 使用者故事 2 - [Brief Title] (Priority: P2)

[Describe this user journey in plain language]

**優先順序理由**: [Explain the value and why it has this priority level]

**獨立測試**: [Describe how this can be tested independently]

**BDD 驗收情境**:

1. **Given** [initial state], **When** [action], **Then** [expected outcome]

---

### 使用者故事 3 - [Brief Title] (Priority: P3)

[Describe this user journey in plain language]

**優先順序理由**: [Explain the value and why it has this priority level]

**獨立測試**: [Describe how this can be tested independently]

**BDD 驗收情境**:

1. **Given** [initial state], **When** [action], **Then** [expected outcome]

---

[視需要加入更多使用者故事，每個故事都必須有優先順序、BDD 驗收情境與獨立測試]

### 邊界案例 (Edge Cases)

<!--
  ACTION REQUIRED: The content in this section represents placeholders.
  Fill them out with the right edge cases.
-->

- What happens when [boundary condition]?
- How does system handle [error scenario]?

## 需求 (Requirements) *(mandatory)*

<!--
  ACTION REQUIRED: The content in this section represents placeholders.
  Fill them out with the right functional requirements.
-->

### 功能需求 (Functional Requirements)

- **FR-001**: System MUST [specific capability, e.g., "allow users to create accounts"]
- **FR-002**: System MUST [specific capability, e.g., "validate email addresses"]
- **FR-003**: Users MUST be able to [key interaction, e.g., "reset their password"]
- **FR-004**: System MUST [data requirement, e.g., "persist user preferences"]
- **FR-005**: System MUST [behavior, e.g., "log all security events"]

*Example of marking unclear requirements:*

- **FR-006**: System MUST authenticate users via [NEEDS CLARIFICATION: auth method not specified - email/password, SSO, OAuth?]
- **FR-007**: System MUST retain user data for [NEEDS CLARIFICATION: retention period not specified]

### 主要實體 (Key Entities) *(include if feature involves data)*

- **[Entity 1]**: [What it represents, key attributes without implementation]
- **[Entity 2]**: [What it represents, relationships to other entities]

## 成功標準 (Success Criteria) *(mandatory)*

<!--
  ACTION REQUIRED: Define measurable success criteria.
  These must be technology-agnostic and measurable.
-->

### 可衡量成果 (Measurable Outcomes)

- **SC-001**: [Measurable metric, e.g., "Users can complete account creation in under 2 minutes"]
- **SC-002**: [Measurable metric, e.g., "System handles 1000 concurrent users without degradation"]
- **SC-003**: [User satisfaction metric, e.g., "90% of users successfully complete primary task on first attempt"]
- **SC-004**: [Business metric, e.g., "Reduce support tickets related to [X] by 50%"]

## 假設 (Assumptions)

<!--
  ACTION REQUIRED: The content in this section represents placeholders.
  Fill them out with the right assumptions based on reasonable defaults
  chosen when the feature description did not specify certain details.
-->

- [Assumption about target users, e.g., "Users have stable internet connectivity"]
- [Assumption about scope boundaries, e.g., "Mobile support is out of scope for v1"]
- [Assumption about data/environment, e.g., "Existing authentication system will be reused"]
- [Dependency on existing system/service, e.g., "Requires access to the existing user profile API"]
