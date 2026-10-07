// TrustDetailView — Full trust breakdown with components, attestations, and contest

import SwiftUI

struct TrustDetailView: View {
    let entityId: UUID
    let isOwnProfile: Bool

    @Environment(AuthViewModel.self) private var auth
    @State private var viewModel: TrustDetailViewModel
    @State private var showContestSheet = false
    @State private var showAttestSheet = false

    init(entityId: UUID, isOwnProfile: Bool = false) {
        self.entityId = entityId
        self.isOwnProfile = isOwnProfile
        self._viewModel = State(initialValue: TrustDetailViewModel(entityId: entityId))
    }

    var body: some View {
        ZStack {
            Color.agBackground.ignoresSafeArea()

            if viewModel.isLoading && viewModel.trustScore == nil {
                LoadingStateView(state: .loading)
            } else if let error = viewModel.error, viewModel.trustScore == nil {
                LoadingStateView(state: .error(message: error, retry: {
                    await viewModel.loadAll()
                }))
            } else {
                ScrollView {
                    VStack(spacing: AGSpacing.lg) {
                        // Overall trust score
                        if let trust = viewModel.trustScore {
                            overallScoreCard(trust)
                            componentBreakdownCard(trust)
                        }

                        // Attestations
                        if !viewModel.attestations.isEmpty {
                            attestationsSection
                        }

                        // Contextual scores
                        if !viewModel.contextualScores.isEmpty {
                            contextualScoresCard
                        }

                        // Actions
                        actionsSection
                    }
                    .padding(.horizontal, AGSpacing.base)
                    .padding(.top, AGSpacing.sm)
                    .padding(.bottom, AGSpacing.xxl)
                }
                .refreshable {
                    await viewModel.loadAll()
                }
            }
        }
        .navigationTitle("Trust Score")
        .navigationBarTitleDisplayMode(.inline)
        .toolbarColorScheme(.dark, for: .navigationBar)
        .task {
            await viewModel.loadAll()
        }
        .sheet(isPresented: $showContestSheet) {
            contestSheet
        }
        .sheet(isPresented: $showAttestSheet) {
            attestSheet
        }
    }

    // MARK: - Overall Score Card

    private func overallScoreCard(_ trust: TrustScoreResponse) -> some View {
        GlassCard {
            VStack(spacing: AGSpacing.lg) {
                Text("Overall Trust Score")
                    .font(AGTypography.lg)
                    .fontWeight(.semibold)
                    .foregroundStyle(Color.agText)

                ZStack {
                    Circle()
                        .stroke(Color.agBorder, lineWidth: 8)
                        .frame(width: 120, height: 120)

                    Circle()
                        .trim(from: 0, to: trust.score)
                        .stroke(
                            scoreColor(trust.score),
                            style: StrokeStyle(lineWidth: 8, lineCap: .round)
                        )
                        .frame(width: 120, height: 120)
                        .rotationEffect(.degrees(-90))

                    VStack(spacing: 2) {
                        Text(String(format: "%.0f", trust.score * 100))
                            .font(.system(size: 36, weight: .bold))
                            .foregroundStyle(scoreColor(trust.score))
                        Text("%")
                            .font(AGTypography.sm)
                            .foregroundStyle(Color.agMuted)
                    }
                }

                Text(HeadlinePhrase.from(score: trust.score))
                    .font(AGTypography.lg)
                    .fontWeight(.bold)
                    .foregroundStyle(HeadlinePhrase.color(score: trust.score))

                HStack(spacing: AGSpacing.sm) {
                    let tier = TrustTierLevel.from(score: trust.score)
                    Image(systemName: tier.attestationIcon)
                        .font(.system(size: 14))
                        .foregroundStyle(tier.color)
                    Text(scoreTier(trust.score))
                        .font(AGTypography.sm)
                        .fontWeight(.medium)
                        .foregroundStyle(scoreColor(trust.score))
                }
                .padding(.horizontal, AGSpacing.md)
                .padding(.vertical, AGSpacing.xs)
                .background(
                    Capsule().fill(scoreColor(trust.score).opacity(0.15))
                )
            }
            .frame(maxWidth: .infinity)
        }
    }

    // MARK: - Component Breakdown

    private func componentBreakdownCard(_ trust: TrustScoreResponse) -> some View {
        GlassCard {
            VStack(alignment: .leading, spacing: AGSpacing.lg) {
                Text("Component Breakdown")
                    .font(AGTypography.lg)
                    .fontWeight(.semibold)
                    .foregroundStyle(Color.agText)

                ForEach(TrustDetailViewModel.componentDefinitions, id: \.key) { def in
                    let rawValue = trust.components?[def.key] ?? 0.0
                    let detail = trust.componentDetails?[def.key]

                    VStack(alignment: .leading, spacing: AGSpacing.xs) {
                        HStack {
                            Text(def.label)
                                .font(AGTypography.sm)
                                .fontWeight(.medium)
                                .foregroundStyle(Color.agText)

                            Spacer()

                            Text(String(format: "%.0f%%", rawValue * 100))
                                .font(AGTypography.sm)
                                .fontWeight(.semibold)
                                .foregroundStyle(scoreColor(rawValue))

                            Text("(\(Int(def.weight * 100))% weight)")
                                .font(AGTypography.xs)
                                .foregroundStyle(Color.agMuted)
                        }

                        ProgressView(value: rawValue)
                            .tint(scoreColor(rawValue))

                        if let detail {
                            Text("Contribution: \(String(format: "%.1f", detail.contribution * 100))%")
                                .font(AGTypography.xs)
                                .foregroundStyle(Color.agMuted)
                        }
                    }

                    if def.key != TrustDetailViewModel.componentDefinitions.last?.key {
                        Divider().background(Color.agBorder)
                    }
                }
            }
        }
    }

    // MARK: - Attestations Section

    private var attestationsSection: some View {
        VStack(alignment: .leading, spacing: AGSpacing.md) {
            HStack {
                Text("Attestations")
                    .font(AGTypography.lg)
                    .fontWeight(.semibold)
                    .foregroundStyle(Color.agText)

                Spacer()

                Text("\(viewModel.attestationCount) total")
                    .font(AGTypography.xs)
                    .foregroundStyle(Color.agMuted)
            }
            .padding(.horizontal, AGSpacing.xs)

            ForEach(viewModel.groupedAttestations, id: \.type) { group in
                GlassCard {
                    VStack(alignment: .leading, spacing: AGSpacing.md) {
                        HStack {
                            Image(systemName: attestationIcon(group.type))
                                .foregroundStyle(Color.agPrimary)
                            Text(group.type.capitalized)
                                .font(AGTypography.base)
                                .fontWeight(.semibold)
                                .foregroundStyle(Color.agText)
                            Spacer()
                            Text("\(group.items.count)")
                                .font(AGTypography.sm)
                                .foregroundStyle(Color.agMuted)
                        }

                        ForEach(group.items) { attestation in
                            VStack(alignment: .leading, spacing: AGSpacing.xs) {
                                HStack {
                                    Text(attestation.attesterDisplayName)
                                        .font(AGTypography.sm)
                                        .fontWeight(.medium)
                                        .foregroundStyle(Color.agText)
                                    Spacer()
                                    Text(String(format: "%.2f", attestation.weight))
                                        .font(AGTypography.xs)
                                        .fontWeight(.semibold)
                                        .foregroundStyle(Color.agPrimary)
                                        .padding(.horizontal, AGSpacing.sm)
                                        .padding(.vertical, 2)
                                        .background(
                                            Capsule().fill(Color.agPrimary.opacity(0.15))
                                        )
                                }

                                if let context = attestation.context {
                                    Text("Context: \(context)")
                                        .font(AGTypography.xs)
                                        .foregroundStyle(Color.agMuted)
                                }

                                if let comment = attestation.comment {
                                    Text(comment)
                                        .font(AGTypography.xs)
                                        .foregroundStyle(Color.agText.opacity(0.8))
                                        .lineLimit(3)
                                }

                                Text(DateFormatting.relativeTime(from: attestation.createdAt))
                                    .font(AGTypography.xs)
                                    .foregroundStyle(Color.agMuted)
                            }
                            .padding(.vertical, AGSpacing.xs)

                            if attestation.id != group.items.last?.id {
                                Divider().background(Color.agBorder)
                            }
                        }
                    }
                }
            }
        }
    }

    // MARK: - Contextual Scores

    private var contextualScoresCard: some View {
        GlassCard {
            VStack(alignment: .leading, spacing: AGSpacing.md) {
                Text("Contextual Attestations")
                    .font(AGTypography.lg)
                    .fontWeight(.semibold)
                    .foregroundStyle(Color.agText)

                ForEach(viewModel.contextualScores, id: \.context) { item in
                    HStack {
                        Text(item.context)
                            .font(AGTypography.sm)
                            .foregroundStyle(Color.agText)
                        Spacer()
                        Text("\(item.count) attestation\(item.count == 1 ? "" : "s")")
                            .font(AGTypography.xs)
                            .foregroundStyle(Color.agPrimary)
                    }

                    if item.context != viewModel.contextualScores.last?.context {
                        Divider().background(Color.agBorder)
                    }
                }
            }
        }
    }

    // MARK: - Actions Section

    private var actionsSection: some View {
        VStack(spacing: AGSpacing.md) {
            // Attest button (only for other entities when authenticated)
            if auth.isAuthenticated && !isOwnProfile {
                Button {
                    showAttestSheet = true
                } label: {
                    HStack {
                        Image(systemName: "checkmark.seal")
                        Text("Create Attestation")
                    }
                    .font(AGTypography.base)
                    .fontWeight(.semibold)
                    .foregroundStyle(.white)
                    .frame(maxWidth: .infinity)
                    .padding(AGSpacing.md)
                    .background(
                        RoundedRectangle(cornerRadius: AGRadii.md)
                            .fill(Color.agPrimary)
                    )
                }
            }

            // Contest button (only for own profile when authenticated)
            if auth.isAuthenticated && isOwnProfile {
                Button {
                    showContestSheet = true
                } label: {
                    HStack {
                        Image(systemName: "exclamationmark.bubble")
                        Text("Contest This Score")
                    }
                    .font(AGTypography.base)
                    .fontWeight(.semibold)
                    .foregroundStyle(Color.agWarning)
                    .frame(maxWidth: .infinity)
                    .padding(AGSpacing.md)
                    .background(
                        RoundedRectangle(cornerRadius: AGRadii.md)
                            .stroke(Color.agWarning, lineWidth: 1)
                    )
                }
            }
        }
    }

    // MARK: - Contest Sheet

    private var contestSheet: some View {
        NavigationStack {
            ZStack {
                Color.agBackground.ignoresSafeArea()

                VStack(spacing: AGSpacing.lg) {
                    if viewModel.contestSubmitted {
                        VStack(spacing: AGSpacing.lg) {
                            Spacer()
                            Image(systemName: "checkmark.circle.fill")
                                .font(.system(size: 48))
                                .foregroundStyle(Color.agSuccess)
                            Text("Contestation Submitted")
                                .font(AGTypography.xl)
                                .fontWeight(.semibold)
                                .foregroundStyle(Color.agText)
                            Text("Your trust score contestation has been submitted for review.")
                                .font(AGTypography.base)
                                .foregroundStyle(Color.agMuted)
                                .multilineTextAlignment(.center)
                            Spacer()
                        }
                    } else {
                        GlassCard {
                            VStack(alignment: .leading, spacing: AGSpacing.md) {
                                Text("Why are you contesting your trust score?")
                                    .font(AGTypography.base)
                                    .fontWeight(.medium)
                                    .foregroundStyle(Color.agText)

                                Text("Provide a detailed reason (minimum 10 characters). Your contestation will be reviewed by moderators.")
                                    .font(AGTypography.sm)
                                    .foregroundStyle(Color.agMuted)

                                TextEditor(text: Binding(
                                    get: { viewModel.contestReason },
                                    set: { viewModel.contestReason = $0 }
                                ))
                                    .scrollContentBackground(.hidden)
                                    .font(AGTypography.base)
                                    .foregroundStyle(Color.agText)
                                    .frame(minHeight: 120)
                                    .padding(AGSpacing.md)
                                    .background(Color.agSurface)
                                    .clipShape(RoundedRectangle(cornerRadius: AGRadii.md))
                                    .overlay(
                                        RoundedRectangle(cornerRadius: AGRadii.md)
                                            .stroke(Color.agBorder, lineWidth: 1)
                                    )

                                if let error = viewModel.contestError {
                                    Text(error)
                                        .font(AGTypography.xs)
                                        .foregroundStyle(Color.agDanger)
                                }
                            }
                        }

                        Button {
                            Task { await viewModel.contestScore() }
                        } label: {
                            if viewModel.isSubmitting {
                                ProgressView()
                                    .tint(.white)
                                    .frame(maxWidth: .infinity)
                                    .padding(AGSpacing.md)
                            } else {
                                Text("Submit Contestation")
                                    .font(AGTypography.base)
                                    .fontWeight(.semibold)
                                    .foregroundStyle(.white)
                                    .frame(maxWidth: .infinity)
                                    .padding(AGSpacing.md)
                            }
                        }
                        .background(
                            RoundedRectangle(cornerRadius: AGRadii.md)
                                .fill(Color.agWarning)
                        )
                        .disabled(viewModel.isSubmitting)
                    }

                    Spacer()
                }
                .padding(AGSpacing.base)
            }
            .navigationTitle("Contest Score")
            .navigationBarTitleDisplayMode(.inline)
            .toolbarColorScheme(.dark, for: .navigationBar)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") {
                        showContestSheet = false
                        viewModel.contestSubmitted = false
                    }
                    .foregroundStyle(Color.agMuted)
                }
            }
        }
    }

    // MARK: - Attest Sheet

    private var attestSheet: some View {
        NavigationStack {
            ZStack {
                Color.agBackground.ignoresSafeArea()

                VStack(spacing: AGSpacing.lg) {
                    if viewModel.attestationCreated {
                        VStack(spacing: AGSpacing.lg) {
                            Spacer()
                            Image(systemName: "checkmark.seal.fill")
                                .font(.system(size: 48))
                                .foregroundStyle(Color.agSuccess)
                            Text("Attestation Created")
                                .font(AGTypography.xl)
                                .fontWeight(.semibold)
                                .foregroundStyle(Color.agText)
                            Text("Your trust attestation has been recorded.")
                                .font(AGTypography.base)
                                .foregroundStyle(Color.agMuted)
                                .multilineTextAlignment(.center)
                            Spacer()
                        }
                    } else {
                        GlassCard {
                            VStack(alignment: .leading, spacing: AGSpacing.md) {
                                Text("Attestation Type")
                                    .font(AGTypography.sm)
                                    .foregroundStyle(Color.agMuted)

                                Picker("Type", selection: Binding(
                                    get: { viewModel.newAttestationType },
                                    set: { viewModel.newAttestationType = $0 }
                                )) {
                                    ForEach(TrustDetailViewModel.attestationTypes, id: \.self) { type in
                                        Text(type.capitalized).tag(type)
                                    }
                                }
                                .pickerStyle(.segmented)

                                Text("Context (optional)")
                                    .font(AGTypography.sm)
                                    .foregroundStyle(Color.agMuted)

                                TextField("e.g. code_review, data_analysis", text: Binding(
                                    get: { viewModel.newAttestationContext },
                                    set: { viewModel.newAttestationContext = $0 }
                                ))
                                    .textFieldStyle(.plain)
                                    .font(AGTypography.base)
                                    .foregroundStyle(Color.agText)
                                    .padding(AGSpacing.md)
                                    .background(Color.agSurface)
                                    .clipShape(RoundedRectangle(cornerRadius: AGRadii.md))
                                    .overlay(
                                        RoundedRectangle(cornerRadius: AGRadii.md)
                                            .stroke(Color.agBorder, lineWidth: 1)
                                    )

                                Text("Comment (optional)")
                                    .font(AGTypography.sm)
                                    .foregroundStyle(Color.agMuted)

                                TextEditor(text: Binding(
                                    get: { viewModel.newAttestationComment },
                                    set: { viewModel.newAttestationComment = $0 }
                                ))
                                    .scrollContentBackground(.hidden)
                                    .font(AGTypography.base)
                                    .foregroundStyle(Color.agText)
                                    .frame(minHeight: 80)
                                    .padding(AGSpacing.md)
                                    .background(Color.agSurface)
                                    .clipShape(RoundedRectangle(cornerRadius: AGRadii.md))
                                    .overlay(
                                        RoundedRectangle(cornerRadius: AGRadii.md)
                                            .stroke(Color.agBorder, lineWidth: 1)
                                    )

                                if let error = viewModel.attestationError {
                                    Text(error)
                                        .font(AGTypography.xs)
                                        .foregroundStyle(Color.agDanger)
                                }
                            }
                        }

                        Button {
                            Task { await viewModel.createAttestation() }
                        } label: {
                            if viewModel.isSubmitting {
                                ProgressView()
                                    .tint(.white)
                                    .frame(maxWidth: .infinity)
                                    .padding(AGSpacing.md)
                            } else {
                                Text("Submit Attestation")
                                    .font(AGTypography.base)
                                    .fontWeight(.semibold)
                                    .foregroundStyle(.white)
                                    .frame(maxWidth: .infinity)
                                    .padding(AGSpacing.md)
                            }
                        }
                        .background(
                            RoundedRectangle(cornerRadius: AGRadii.md)
                                .fill(Color.agPrimary)
                        )
                        .disabled(viewModel.isSubmitting)
                    }

                    Spacer()
                }
                .padding(AGSpacing.base)
            }
            .navigationTitle("Create Attestation")
            .navigationBarTitleDisplayMode(.inline)
            .toolbarColorScheme(.dark, for: .navigationBar)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") {
                        showAttestSheet = false
                        viewModel.attestationCreated = false
                    }
                    .foregroundStyle(Color.agMuted)
                }
            }
        }
    }

    // MARK: - Helpers

    private func scoreColor(_ score: Double) -> Color {
        TrustTierLevel.from(score: score).color
    }

    private func scoreTier(_ score: Double) -> String {
        TrustTierLevel.from(score: score).attestationLabel
    }

    private func attestationIcon(_ type: String) -> String {
        switch type {
        case "competent": return "brain.head.profile"
        case "reliable": return "clock.badge.checkmark"
        case "safe": return "shield.checkered"
        case "responsive": return "bolt.fill"
        default: return "checkmark.seal"
        }
    }
}
