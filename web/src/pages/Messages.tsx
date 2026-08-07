import { useState, useEffect, useRef, type FormEvent, type ReactNode } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import api from '../lib/api'
import { useAuth } from '../hooks/useAuth'
import ConfirmDialog from '../components/ConfirmDialog'
import { useToast } from '../components/Toasts'
import { getApiErrorMessage } from '../lib/errors'
import { timeAgo } from '../lib/formatters'

const URL_RE = /(https?:\/\/[^\s<]+)/

function linkify(text: string): ReactNode[] {
  const parts = text.split(URL_RE)
  return parts.map((part, i) =>
    URL_RE.test(part) ? (
      <a key={i} href={part} target="_blank" rel="noopener noreferrer" className="underline hover:opacity-80">{part}</a>
    ) : (
      part
    ),
  )
}

interface Conversation {
  id: string
  other_entity_id: string
  other_entity_name: string
  other_entity_type: string
  last_message_preview: string | null
  last_message_at: string
  unread_count: number
}

interface Message {
  id: string
  conversation_id: string
  sender_id: string
  sender_name: string
  content: string
  is_read: boolean
  created_at: string
}

interface SearchEntity {
  id: string
  type: string
  display_name: string
  did_web: string
}

export default function Messages() {
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const { addToast } = useToast()
  const [searchParams, setSearchParams] = useSearchParams()
  const [selectedConvId, setSelectedConvId] = useState<string | null>(null)
  const [messageText, setMessageText] = useState('')
  const [showCompose, setShowCompose] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [showConvList, setShowConvList] = useState(true)
  const [composeRecipient, setComposeRecipient] = useState<{ id: string; name: string } | null>(null)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const toHandledRef = useRef(false)

  useEffect(() => { document.title = 'Messages - AgentAvow' }, [])

  const conversationsQuery = useQuery<{ conversations: Conversation[]; total: number }>({
    queryKey: ['conversations'],
    queryFn: async () => {
      const { data } = await api.get('/messages', { params: { limit: 50 } })
      return data
    },
    staleTime: 30_000,
    refetchOnWindowFocus: true,
  })

  // Handle ?to= param: open existing conversation or compose to that user
  const toEntityId = searchParams.get('to')
  useEffect(() => {
    if (!toEntityId || toHandledRef.current) return
    if (!conversationsQuery.data) return // wait for conversations to load

    // Check if we already have a conversation with this user
    const existing = conversationsQuery.data.conversations.find(
      (c) => c.other_entity_id === toEntityId
    )
    if (existing) {
      setSelectedConvId(existing.id)
      setShowConvList(false)
    } else {
      // Open compose mode and fetch the recipient's profile
      setShowCompose(true)
      setShowConvList(false)
      api.get(`/profiles/${toEntityId}`).then(({ data }) => {
        setComposeRecipient({ id: toEntityId, name: data.display_name })
      }).catch(() => {
        // If profile fetch fails, still allow composing
        setComposeRecipient({ id: toEntityId, name: 'Unknown User' })
      })
    }
    toHandledRef.current = true
    // Clear the to param from URL
    setSearchParams({}, { replace: true })
  }, [toEntityId, conversationsQuery.data, setSearchParams])

  const messagesQuery = useQuery<{ messages: Message[] }>({
    queryKey: ['messages', selectedConvId],
    queryFn: async () => {
      const { data } = await api.get(`/messages/${selectedConvId}`, { params: { limit: 100 } })
      return data
    },
    enabled: !!selectedConvId,
    staleTime: 10_000,
    refetchOnWindowFocus: true,
  })

  const searchResultsQuery = useQuery<{ entities: SearchEntity[] }>({
    queryKey: ['dm-search', searchQuery],
    queryFn: async () => {
      const { data } = await api.get('/search', { params: { q: searchQuery, type: 'all' } })
      return data
    },
    enabled: searchQuery.length >= 2,
    staleTime: 30_000,
  })

  const conversations = conversationsQuery.data
  const messages = messagesQuery.data
  const searchResults = searchResultsQuery.data

  const sendMessage = useMutation({
    mutationFn: async ({ recipientId, content }: { recipientId: string; content: string }) => {
      const { data } = await api.post('/messages', { recipient_id: recipientId, content })
      return data
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['messages', selectedConvId || data.conversation_id] })
      queryClient.invalidateQueries({ queryKey: ['conversations'] })
      setMessageText('')
      if (!selectedConvId && data.conversation_id) {
        setSelectedConvId(data.conversation_id)
        setShowCompose(false)
        setSearchQuery('')
      }
    },
    onError: (err: unknown) => {
      addToast(getApiErrorMessage(err, 'Failed to send message'), 'error')
    },
  })

  const [deleteMessageId, setDeleteMessageId] = useState<string | null>(null)
  const [deleteConvId, setDeleteConvId] = useState<string | null>(null)

  const deleteMessageMutation = useMutation({
    mutationFn: async (messageId: string) => {
      await api.delete(`/messages/${selectedConvId}/messages/${messageId}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['messages', selectedConvId] })
      queryClient.invalidateQueries({ queryKey: ['conversations'] })
      setDeleteMessageId(null)
      addToast('Message deleted', 'success')
    },
    onError: () => {
      addToast('Failed to delete message', 'error')
    },
  })

  const deleteConvMutation = useMutation({
    mutationFn: async (convId: string) => {
      await api.delete(`/messages/${convId}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['conversations'] })
      setSelectedConvId(null)
      setShowConvList(true)
      setDeleteConvId(null)
    },
    onError: () => {
      addToast('Failed to delete conversation', 'error')
    },
  })

  const selectedConv = conversations?.conversations.find((c) => c.id === selectedConvId)

  // Scroll to bottom when messages change
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages?.messages.length])

  const selectConversation = (convId: string) => {
    setSelectedConvId(convId)
    setShowCompose(false)
    setShowConvList(false)
  }

  const startCompose = () => {
    setShowCompose(true)
    setSelectedConvId(null)
    setSearchQuery('')
    setComposeRecipient(null)
    setShowConvList(false)
  }

  const handleSend = (e: FormEvent) => {
    e.preventDefault()
    if (!messageText.trim()) return
    if (selectedConv) {
      sendMessage.mutate({ recipientId: selectedConv.other_entity_id, content: messageText })
    }
  }

  const totalUnread = conversations?.conversations.reduce((sum, c) => sum + c.unread_count, 0) || 0

  const isLoading = conversationsQuery.isLoading || messagesQuery.isLoading || searchResultsQuery.isLoading
  const hasError = conversationsQuery.isError || messagesQuery.isError || searchResultsQuery.isError

  if (isLoading) return <div className="flex justify-center py-20"><div className="animate-spin h-8 w-8 border-2 border-primary border-t-transparent rounded-full" /></div>
  if (hasError) return <div className="text-center py-20"><p className="text-text-muted mb-4">Failed to load messages</p><button onClick={() => { conversationsQuery.refetch(); messagesQuery.refetch(); searchResultsQuery.refetch() }} className="text-primary hover:underline">Try again</button></div>

  return (
    <div className="flex flex-1 min-h-0 gap-0 md:gap-4 overflow-hidden">
      {/* Conversation list — hidden on mobile when viewing a thread */}
      <div className={`${!showConvList && (selectedConvId || showCompose) ? 'hidden md:block' : ''} w-full md:w-72 shrink-0 bg-surface border border-border rounded-lg overflow-auto`}>
        <div className="p-3 border-b border-border flex items-center justify-between">
          <h2 className="text-sm font-semibold">
            Messages
            {totalUnread > 0 && (
              <span className="ml-1.5 text-[10px] bg-primary text-white px-1.5 py-0.5 rounded-full">
                {totalUnread}
              </span>
            )}
          </h2>
          <button
            onClick={startCompose}
            className="text-xs bg-primary hover:bg-primary-dark text-white px-2.5 py-1 rounded transition-colors cursor-pointer"
          >
            New
          </button>
        </div>
        <div className="divide-y divide-border">
          {conversations?.conversations.map((conv) => (
            <button
              key={conv.id}
              onClick={() => selectConversation(conv.id)}
              className={`w-full text-left p-3 hover:bg-surface-hover transition-colors cursor-pointer ${
                selectedConvId === conv.id ? 'bg-surface-hover' : ''
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-1.5 min-w-0">
                  <span className={`text-sm truncate ${conv.unread_count > 0 ? 'font-semibold text-text' : 'font-medium'}`}>
                    {conv.other_entity_name}
                  </span>
                  <span className={`shrink-0 px-1 py-0.5 rounded text-[9px] uppercase tracking-wider ${
                    conv.other_entity_type === 'agent' ? 'bg-blue-400/20 text-blue-400' : 'bg-success/20 text-success'
                  }`}>
                    {conv.other_entity_type}
                  </span>
                </div>
                <span className="text-[10px] text-text-muted shrink-0 ml-2">{timeAgo(conv.last_message_at)}</span>
              </div>
              <div className="flex items-center justify-between mt-0.5">
                <span className="text-xs text-text-muted truncate">
                  {conv.last_message_preview || 'No messages'}
                </span>
                {conv.unread_count > 0 && (
                  <span className="bg-primary text-white text-[10px] px-1.5 py-0.5 rounded-full ml-1 shrink-0">
                    {conv.unread_count}
                  </span>
                )}
              </div>
            </button>
          ))}
          {(!conversations || conversations.conversations.length === 0) && (
            <div className="p-4 text-xs text-text-muted text-center">
              No conversations yet. Start one!
            </div>
          )}
        </div>
      </div>

      {/* Message thread / Compose */}
      <div className={`${showConvList && !selectedConvId && !showCompose ? 'hidden md:flex' : 'flex'} flex-1 bg-surface border border-border rounded-lg flex-col min-w-0`}>
        {showCompose ? (
          <>
            <div className="p-3 border-b border-border">
              <div className="flex items-center gap-2 mb-2">
                <button
                  onClick={() => { setShowCompose(false); setComposeRecipient(null); setShowConvList(true) }}
                  className="md:hidden text-xs text-text-muted hover:text-text cursor-pointer"
                >
                  &larr; Back
                </button>
                <span className="text-sm font-semibold">New Message</span>
              </div>
              {composeRecipient ? (
                <div className="flex items-center gap-2 bg-background border border-border rounded-md px-3 py-2">
                  <span className="text-sm text-text-muted">To:</span>
                  <span className="text-sm font-medium">{composeRecipient.name}</span>
                  <button
                    onClick={() => setComposeRecipient(null)}
                    className="ml-auto text-xs text-text-muted hover:text-text cursor-pointer"
                  >
                    &times;
                  </button>
                </div>
              ) : (
                <input
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search for a user or agent..."
                  aria-label="Search for a user or agent"
                  autoFocus
                  className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm text-text focus:outline-none focus:border-primary"
                />
              )}
            </div>
            {!composeRecipient && searchQuery.length >= 2 && searchResults?.entities && (
              <div className="border-b border-border max-h-60 overflow-auto">
                {searchResults.entities
                  .filter((e) => e.id !== user?.id)
                  .map((entity) => (
                    <div
                      key={entity.id}
                      className="p-3 hover:bg-surface-hover transition-colors flex items-center justify-between cursor-pointer"
                      onClick={() => {
                        setComposeRecipient({ id: entity.id, name: entity.display_name })
                        setSearchQuery('')
                      }}
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="text-sm font-medium truncate">{entity.display_name}</span>
                        <span className={`px-1 py-0.5 rounded text-[9px] uppercase tracking-wider ${
                          entity.type === 'agent' ? 'bg-blue-400/20 text-blue-400' : 'bg-success/20 text-success'
                        }`}>
                          {entity.type}
                        </span>
                      </div>
                    </div>
                  ))}
                {searchResults.entities.filter((e) => e.id !== user?.id).length === 0 && (
                  <div className="p-3 text-xs text-text-muted text-center">No users found</div>
                )}
              </div>
            )}
            <div className="flex-1" />
            <div className="p-3 border-t border-border">
              <form onSubmit={(e) => {
                e.preventDefault()
                if (composeRecipient && messageText.trim()) {
                  sendMessage.mutate({ recipientId: composeRecipient.id, content: messageText })
                }
              }} className="flex flex-col gap-2">
                <textarea
                  value={messageText}
                  onChange={(e) => setMessageText(e.target.value)}
                  placeholder={composeRecipient ? `Message ${composeRecipient.name}...` : 'Write your message first, then pick a recipient above...'}
                  aria-label="Compose new message"
                  autoFocus={!!composeRecipient}
                  rows={3}
                  maxLength={5000}
                  className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm text-text focus:outline-none focus:border-primary resize-none"
                />
                {composeRecipient && (
                  <button
                    type="submit"
                    disabled={!messageText.trim() || sendMessage.isPending}
                    className="self-end bg-primary hover:bg-primary-dark text-white px-4 py-2 rounded-md text-sm transition-colors disabled:opacity-50 cursor-pointer"
                  >
                    {sendMessage.isPending ? 'Sending...' : 'Send'}
                  </button>
                )}
              </form>
            </div>
          </>
        ) : selectedConv ? (
          <>
            <div className="p-3 border-b border-border flex items-center gap-2">
              <button
                onClick={() => { setSelectedConvId(null); setShowConvList(true) }}
                className="md:hidden text-xs text-text-muted hover:text-text cursor-pointer"
              >
                &larr; Back
              </button>
              <Link
                to={`/profile/${selectedConv.other_entity_id}`}
                className="text-sm font-medium hover:text-primary-light transition-colors"
              >
                {selectedConv.other_entity_name}
              </Link>
              <span className={`px-1.5 py-0.5 rounded text-[10px] uppercase tracking-wider ${
                selectedConv.other_entity_type === 'agent' ? 'bg-blue-400/20 text-blue-400' : 'bg-success/20 text-success'
              }`}>
                {selectedConv.other_entity_type}
              </span>
              <button
                onClick={() => setDeleteConvId(selectedConv.id)}
                className="ml-auto text-[10px] text-text-muted hover:text-danger transition-colors cursor-pointer"
                title="Delete conversation"
              >
                Delete
              </button>
            </div>
            <div className="flex-1 overflow-auto p-4 space-y-3 flex flex-col">
              {(() => {
                const reversed = [...(messages?.messages || [])].reverse()
                // Find the last message sent by current user that was read
                let lastReadIdx = -1
                for (let i = reversed.length - 1; i >= 0; i--) {
                  if (reversed[i].sender_id === user?.id && reversed[i].is_read) {
                    lastReadIdx = i
                    break
                  }
                }
                return reversed.map((msg, idx) => (
                  <div key={msg.id}>
                    <div
                      className={`group flex items-end gap-1 ${msg.sender_id === user?.id ? 'justify-end' : 'justify-start'}`}
                    >
                      {msg.sender_id === user?.id && (
                        <button
                          onClick={() => setDeleteMessageId(msg.id)}
                          className="opacity-0 group-hover:opacity-100 text-[10px] text-text-muted hover:text-danger transition-all cursor-pointer mb-1"
                        >
                          Delete
                        </button>
                      )}
                      <div className={`max-w-[75%] px-3 py-2 rounded-lg text-sm ${
                        msg.sender_id === user?.id
                          ? 'bg-primary text-white rounded-br-sm'
                          : 'bg-background text-text rounded-bl-sm'
                      }`}>
                        <p className="break-words whitespace-pre-wrap">{linkify(msg.content)}</p>
                        <span className={`text-[10px] mt-1 block ${
                          msg.sender_id === user?.id ? 'text-white/60' : 'text-text-muted'
                        }`}>
                          {timeAgo(msg.created_at)}
                        </span>
                      </div>
                    </div>
                    {idx === lastReadIdx && (
                      <div className="text-[10px] text-text-muted text-right mt-0.5">Seen</div>
                    )}
                  </div>
                ))
              })()}
              <div ref={messagesEndRef} />
            </div>
            {selectedConv.other_entity_type === 'agent' ? (
              <div className="p-3 border-t border-border text-center">
                <p className="text-xs text-text-muted">This is an automated message. Bot conversations are read-only.</p>
              </div>
            ) : (
              <div className="p-3 border-t border-border">
                <form onSubmit={handleSend} className="flex gap-2">
                  <input
                    value={messageText}
                    onChange={(e) => setMessageText(e.target.value)}
                    onKeyDown={(e) => {
                      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter' && messageText.trim()) {
                        e.preventDefault()
                        if (selectedConv) {
                          sendMessage.mutate({ recipientId: selectedConv.other_entity_id, content: messageText })
                        }
                      }
                    }}
                    placeholder="Type a message..."
                    aria-label="Type a message"
                    maxLength={5000}
                    className="flex-1 bg-background border border-border rounded-md px-3 py-2 text-sm text-text focus:outline-none focus:border-primary"
                  />
                  <button
                    type="submit"
                    disabled={!messageText.trim() || sendMessage.isPending}
                    className="bg-primary hover:bg-primary-dark text-white px-4 py-2 rounded-md text-sm transition-colors disabled:opacity-50 cursor-pointer"
                    title="Ctrl+Enter to send"
                  >
                    Send
                  </button>
                </form>
                {messageText.length > 4000 && (
                  <span className={`text-[10px] ${messageText.length >= 5000 ? 'text-danger' : 'text-text-muted'}`}>
                    {messageText.length}/5000
                  </span>
                )}
              </div>
            )}
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center text-text-muted text-sm">
            Select a conversation or start a new one
          </div>
        )}
      </div>

      {deleteMessageId && (
        <ConfirmDialog
          title="Delete Message"
          message="Are you sure you want to delete this message? This cannot be undone."
          variant="danger"
          confirmLabel="Delete"
          isPending={deleteMessageMutation.isPending}
          onConfirm={() => deleteMessageMutation.mutate(deleteMessageId)}
          onCancel={() => setDeleteMessageId(null)}
        />
      )}

      {deleteConvId && (
        <ConfirmDialog
          title="Delete Conversation"
          message="Are you sure you want to delete this entire conversation? All messages will be permanently removed."
          variant="danger"
          confirmLabel="Delete Conversation"
          isPending={deleteConvMutation.isPending}
          onConfirm={() => deleteConvMutation.mutate(deleteConvId)}
          onCancel={() => setDeleteConvId(null)}
        />
      )}
    </div>
  )
}
