import { useState } from 'react';
import { Client } from '../../types';
import { useDataPersistence } from '../../hooks/useDataPersistence';
import { generateId } from '../../utils/formatters';
import { mockClients } from '../../data/mockData';

export function useClients() {
  const [clients, setClients] = useDataPersistence('firmflowz-clients', mockClients);
  const [showNewClientForm, setShowNewClientForm] = useState(false);

  const handleAddClient = (clientData: Omit<Client, 'id'>) => {
    const newClient: Client = {
      ...clientData,
      id: generateId()
    };
    setClients(prev => [...prev, newClient]);
    setShowNewClientForm(false);
  };

  const handleUpdateClient = (id: string, updates: Partial<Client>) => {
    setClients(prev => prev.map(client => 
      client.id === id ? { ...client, ...updates } : client
    ));
  };

  const handleDeleteClient = (id: string) => {
    setClients(prev => prev.filter(client => client.id !== id));
  };

  return {
    clients,
    showNewClientForm,
    setShowNewClientForm,
    handleAddClient,
    handleUpdateClient,
    handleDeleteClient
  };
}