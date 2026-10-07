// FeedView — Trust-scored content stream with real data and navigation

import SwiftUI

struct FeedView: View {
    @Environment(AuthViewModel.self) private var auth
    @State private var viewModel = FeedViewModel()
    @State private var showCompose = false
    @State private var showLoginPrompt = false
    @State private var notificationsVM = NotificationsViewModel()
    @State private var messagesVM = MessagesViewModel()
    @State private var wsState: WebSocketService.ConnectionState = .disconnected

    var body: some View {
        NavigationStack {
            ZStack(alignment: .bottomTrailing) {
                ScrollView {
                    LazyVStack(spacing: AGSpacing.base) {
                        // Feed mode picker
                        Picker("Feed", selection: Binding(
                            get: { viewModel.feedMode },
                            set: { mode in Task { await viewModel.switchMode(mode) } }
                        )) {
                            ForEach(FeedMode.allCases, id: \.self) { mode in
                                Text(mode.rawValue).tag(mode)
                            }
                        }
                        .pickerStyle(.segmented)
                        .padding(.horizontal, AGSpacing.sm)

                        if let error = viewModel.error {
                            LoadingStateView(state: .error(message: error, retry: {
                                await viewModel.refresh()
                            }))
                        } else if viewModel.posts.isEmpty && !viewModel.isLoading {
                            LoadingStateView(state: .empty(message: "No posts yet. Start the conversation!"))
                        } else {
                            ForEach(viewModel.posts) { post in
                                NavigationLink(value: post.id) {
                                    PostCard(
                                        post: post,
                                        onVote: auth.isAuthenticated ? { direction in
                                            Task { await viewModel.vote(postId: post.id, direction: direction) }
                                        } : { _ in showLoginPrompt = true },
                                        onBookmark: auth.isAuthenticated ? {
                                            Task { await viewModel.bookmark(postId: post.id) }
                                        } : { showLoginPrompt = true }
                                    )
                                }
                                .buttonStyle(.plain)
                                // #1: Pagination trigger
                                .onAppear {
                                    Task { await viewModel.loadMoreIfNeeded(currentPost: post) }
                                }
                            }
                        }

                        if viewModel.isLoading {
                            ProgressView()
                                .tint(.agPrimary)
                                .padding()
                        }
                    }
                    .padding(.horizontal, AGSpacing.base)
                    .padding(.top, AGSpacing.sm)
                }
                .background(Color.agBackground)

                // Compose FAB — authenticated only
                if auth.isAuthenticated {
                    Button {
                        showCompose = true
                    } label: {
                        Image(systemName: "plus")
                            .font(.system(size: 20, weight: .bold))
                            .foregroundStyle(.white)
                            .frame(width: 56, height: 56)
                            .background(
                                Circle().fill(
                                    LinearGradient(
                                        colors: [.agPrimary, .agAccent],
                                        startPoint: .topLeading,
                                        endPoint: .bottomTrailing
                                    )
                                )
                            )
                            .shadow(color: .agPrimary.opacity(0.4), radius: 8, y: 4)
                    }
                    .padding(.trailing, AGSpacing.lg)
                    .padding(.bottom, AGSpacing.lg)
                }
            }
            .navigationTitle("Feed")
            .toolbarColorScheme(.dark, for: .navigationBar)
            .toolbar {
                if auth.isAuthenticated {
                    ToolbarItem(placement: .topBarLeading) {
                        ConnectionDot(state: wsState)
                    }
                    ToolbarItem(placement: .primaryAction) {
                        HStack(spacing: AGSpacing.md) {
                            NavigationLink {
                                ConversationsListView()
                            } label: {
                                ZStack(alignment: .topTrailing) {
                                    Image(systemName: "envelope")
                                    if messagesVM.unreadCount > 0 {
                                        Text(messagesVM.unreadCount > 99 ? "99+" : "\(messagesVM.unreadCount)")
                                            .font(.system(size: 10, weight: .bold))
                                            .foregroundStyle(.white)
                                            .padding(3)
                                            .background(Circle().fill(Color.agDanger))
                                            .offset(x: 8, y: -8)
                                    }
                                }
                            }
                            .tint(.agPrimary)

                            NavigationLink {
                                NotificationsView()
                            } label: {
                                ZStack(alignment: .topTrailing) {
                                    Image(systemName: "bell")
                                    if notificationsVM.unreadCount > 0 {
                                        // #30: Cap badge at 99+
                                        Text(notificationsVM.unreadCount > 99 ? "99+" : "\(notificationsVM.unreadCount)")
                                            .font(.system(size: 10, weight: .bold))
                                            .foregroundStyle(.white)
                                            .padding(3)
                                            .background(Circle().fill(Color.agDanger))
                                            .offset(x: 8, y: -8)
                                    }
                                }
                            }
                            .tint(.agPrimary)
                        }
                    }
                }
            }
            .navigationDestination(for: UUID.self) { postId in
                PostDetailView(postId: postId)
            }
            .refreshable {
                await viewModel.refresh()
            }
            .sheet(isPresented: $showCompose) {
                ComposePostView {
                    await viewModel.refresh()
                }
            }
            .alert("Sign In Required", isPresented: $showLoginPrompt) {
                Button("Sign In") {
                    AnalyticsService.shared.trackEvent(type: "guest_cta_click", page: "feed", intent: "sign_in_alert")
                    // #12: exitGuestMode instead of logout
                    auth.exitGuestMode()
                }
                Button("Cancel", role: .cancel) { }
            } message: {
                Text("Create an account or sign in to vote, post, and interact.")
            }
            .task {
                if !auth.isAuthenticated {
                    AnalyticsService.shared.trackEvent(type: "guest_page_view", page: "feed")
                }
                await viewModel.loadFeed()
                await viewModel.subscribeToLiveUpdates()
            }
            .task(id: auth.isAuthenticated) {
                // #21: Poll notifications periodically when authenticated
                // WebSocket provides instant updates; polling is the fallback
                if auth.isAuthenticated {
                    await notificationsVM.subscribeToLiveUpdates()
                    await notificationsVM.startPolling()
                }
            }
            .task(id: auth.isAuthenticated) {
                if auth.isAuthenticated {
                    await messagesVM.loadUnreadCount()
                    await messagesVM.startPolling()
                }
            }
            .task {
                // Periodically refresh connection status dot
                while !Task.isCancelled {
                    wsState = await WebSocketService.shared.getState()
                    try? await Task.sleep(for: .seconds(3))
                }
            }
        }
    }
}

// MARK: - Trust Tier System

/// Tier level (0-5) computed from a 0-1 trust score
enum TrustTierLevel: Int, CaseIterable {
    case unverified = 0
    case basic = 1
    case confirmed = 2
    case validated = 3
    case verified = 4
    case certified = 5

    static func from(score: Double) -> TrustTierLevel {
        let pct = score * 100
        if pct >= 90 { return .certified }
        if pct >= 80 { return .verified }
        if pct >= 60 { return .validated }
        if pct >= 40 { return .confirmed }
        if pct >= 20 { return .basic }
        return .unverified
    }

    var color: Color {
        switch self {
        case .unverified: return Color(red: 108/255, green: 112/255, blue: 134/255)
        case .basic: return Color(red: 245/255, green: 158/255, blue: 11/255)
        case .confirmed: return Color(red: 13/255, green: 148/255, blue: 136/255)
        case .validated: return Color(red: 45/255, green: 212/255, blue: 191/255)
        case .verified: return .agAccent
        case .certified: return Color(red: 245/255, green: 158/255, blue: 11/255)
        }
    }

    var attestationLabel: String {
        switch self {
        case .unverified: return "Unverified"
        case .basic: return "Basic"
        case .confirmed: return "Confirmed"
        case .validated: return "Validated"
        case .verified: return "Verified"
        case .certified: return "Certified"
        }
    }

    var communityLabel: String {
        switch self {
        case .unverified: return "Unknown"
        case .basic: return "Emerging"
        case .confirmed: return "Connected"
        case .validated: return "Established"
        case .verified: return "Trusted"
        case .certified: return "Pillar"
        }
    }

    /// SF Symbol for attestation (shield) axis
    var attestationIcon: String {
        switch self {
        case .unverified: return "shield.slash"
        case .basic: return "shield"
        case .confirmed: return "shield.checkered"
        case .validated: return "shield.lefthalf.filled"
        case .verified: return "shield.fill"
        case .certified: return "shield.fill"
        }
    }

    /// SF Symbol for community (network) axis
    var communityIcon: String {
        switch self {
        case .unverified: return "circle.dotted"
        case .basic: return "person.2"
        case .confirmed: return "person.3"
        case .validated: return "person.3.fill"
        case .verified: return "hexagon"
        case .certified: return "sparkles"
        }
    }
}

// MARK: - Headline phrase (three-phrase decision)

/// The three headline phrases every AgentAvow surface leads with (src/trust_tiers.py
/// DECISIONS). The app shows a score without the findings behind it, so it can only
/// apply the score part of the rule: under 51 reads "Review before you connect".
/// The tier word stays as detail underneath; Certified stays where it is.
enum HeadlinePhrase {
    static let safe = "Safe to connect"
    static let review = "Review before you connect"
    static let doNotConnect = "Do not connect"

    static func from(score: Double) -> String {
        return score * 100 < 51 ? review : safe
    }

    static func color(score: Double) -> Color {
        return score * 100 < 51
            ? Color(red: 245/255, green: 158/255, blue: 11/255)
            : Color(red: 34/255, green: 197/255, blue: 94/255)
    }
}

// MARK: - Trust Badge (Tier-Aware)

struct TrustBadge: View {
    let score: Double
    var showLabel: Bool = false

    private var tier: TrustTierLevel {
        TrustTierLevel.from(score: score)
    }

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: tier.attestationIcon)
                .font(.system(size: 10))
            Text(String(format: "%.0f", score * 100))
                .font(AGTypography.xs)
                .fontWeight(.semibold)
            if showLabel {
                Text(tier.attestationLabel)
                    .font(.system(size: 9))
            }
        }
        .foregroundStyle(.white)
        .padding(.horizontal, AGSpacing.sm)
        .padding(.vertical, AGSpacing.xs)
        .background(
            Capsule().fill(tier.color.opacity(0.8))
        )
    }
}

// MARK: - Entity Avatar Shape

struct EntityAvatarShape: ViewModifier {
    let entityType: String

    func body(content: Content) -> some View {
        if entityType == "agent" {
            content.clipShape(AgentHexShape())
        } else {
            content.clipShape(Circle())
        }
    }
}

/// Hexagonal clip shape for agent avatars
struct AgentHexShape: Shape {
    func path(in rect: CGRect) -> Path {
        let w = rect.width
        let h = rect.height
        var path = Path()
        path.move(to: CGPoint(x: w * 0.5, y: 0))
        path.addLine(to: CGPoint(x: w, y: h * 0.25))
        path.addLine(to: CGPoint(x: w, y: h * 0.75))
        path.addLine(to: CGPoint(x: w * 0.5, y: h))
        path.addLine(to: CGPoint(x: 0, y: h * 0.75))
        path.addLine(to: CGPoint(x: 0, y: h * 0.25))
        path.closeSubpath()
        return path
    }
}

extension View {
    func entityAvatarShape(_ entityType: String) -> some View {
        modifier(EntityAvatarShape(entityType: entityType))
    }
}
